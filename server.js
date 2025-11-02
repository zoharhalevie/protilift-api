// server.js — API קטן לאימות Google ומעקב סשן

const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// לוג פשוט לכל בקשה
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ====== CONFIG ======
const 413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com = process.env.IOS_CLIENT_ID || '';   // לדוגמה: 4136...apps.googleusercontent.com
const 413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com = process.env.WEB_CLIENT_ID || '';   // לדוגמה: 4136...apps.googleusercontent.com

// ====== זיכרון לסשנים (לבדיקות/POC). בפרודקשן שים Redis/DB ======
/** @type {Map<string, {email:string, sub:string, createdAt:number}>} */
const sessions = new Map();

// ====== עזר ======
function makeSid() {
  return crypto.randomUUID().replace(/-/g, '');
}
function getSidFromAnywhere(req) {
  return (
    req.cookies?.session ||
    req.get('x-session') ||
    req.query.session ||
    (req.body && req.body.session) ||
    null
  );
}

// ====== בריאות/דיבוג ======
app.get('/', (_, res) => res.send('OK'));
app.get('/ok', (_, res) => res.send('OK'));
app.get('/hello', (_, res) => {
  res.json({
    ok: true,
    from: 'node',
    ts: Date.now(),
    env: {
      hasIOS: !!IOS_CLIENT_ID,
      hasWEB: !!WEB_CLIENT_ID,
    },
  });
});
app.get('/debug-config', (_, res) => {
  res.json({
    ok: true,
    IOS_CLIENT_ID: IOS_CLIENT_ID || '(missing)',
    WEB_CLIENT_ID: WEB_CLIENT_ID || '(missing)',
    sessionsCount: sessions.size,
  });
});

// ====== אימות Google ID Token ======
// iOS → תשלח platform = "ios"
// Web  → תשלח platform = "web" (או תשאיר ריק — יחשב כ-web)
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken, platform } = req.body || {};
    if (!idToken) {
      return res.status(400).json({ ok: false, err: 'missing idToken' });
    }
    const isIOS = String(platform || '').toLowerCase() === 'ios';
    const expectedAud = isIOS ? IOS_CLIENT_ID : WEB_CLIENT_ID;
    if (!expectedAud) {
      return res.status(500).json({ ok: false, err: 'server missing client id env' });
    }

    // מאמתים את ה-idToken מול ה-audience המתאים
    const client = new OAuth2Client(expectedAud);
    const ticket = await client.verifyIdToken({
      idToken,
      audience: expectedAud,
    });
    const payload = ticket.getPayload(); // email, sub, aud, exp, ...
    const email = payload.email || '';
    const sub = payload.sub || '';

    // נוציא sid ונשמור בזיכרון
    const sid = makeSid();
    sessions.set(sid, { email, sub, createdAt: Date.now() });

    // הערה חשובה:
    // כאן אנחנו לא מגדירים cookie ל-domain של protilift.com,
    // כי דפדפן מרחוק (railway.app) לא יכול לקבוע cookie עבור דומיין אחר.
    // את ה-cookie תשבץ באפליקציית iOS (WKHTTPCookieStore) או בצד האתר,
    // ואנחנו נחזיר לך את ה-sid בגוף.
    return res.json({ ok: true, sid, email, sub });
  } catch (err) {
    console.error('verify idToken error:', err?.message || err);
    return res.status(401).json({ ok: false, err: 'invalid token' });
  }
});

// ====== ולבקשתך: בדיקת סשן ו־whoami ======

// בדיקת סשן — מוודא שה-sid תקף ומחזיר את המשתמש
app.get('/api/auth/session/validate', (req, res) => {
  const sid = getSidFromAnywhere(req);
  if (!sid) return res.status(401).json({ ok: false, err: 'no sid' });

  const user = sessions.get(sid);
  if (!user) return res.status(401).json({ ok: false, err: 'invalid sid' });

  return res.json({ ok: true, user });
});

// למעקב עצמי / דיבוג מהיר: לראות האם מגיע sid ואיך
app.get('/whoami', (req, res) => {
  const sid =
    req.cookies?.session ||
    req.get('x-session') ||
    req.query.session ||
    (req.body && req.body.session) ||
    null;

  const user = sid ? sessions.get(sid) : null;
  res.json({
    hasCookie: !!req.cookies?.session,
    fromHeader: !!req.get('x-session'),
    fromQuery: !!req.query.session,
    sid: sid || null,
    loggedIn: !!user,
    user,
  });
});

// ====== הפעלה ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`listening on http://localhost:${PORT}`);
});
