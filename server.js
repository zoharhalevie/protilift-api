// server.js — protilift pilot (v4.1)
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cookieParser());

// לוג לכל בקשה
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/* ====== החלף כאן לערכים האמיתיים שלך, עם מרכאות ====== */
const IOS_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
const WEB_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
/* ====================================================== */

// ולידציה כדי לתפוס טעויות בפורמט
function assertCID(name, value) {
  if (typeof value !== 'string') throw new Error(`${name} must be a string (missing quotes?)`);
  if (!value.includes('.apps.googleusercontent.com')) throw new Error(`${name} looks wrong: ${value}`);
}
assertCID('IOS_CLIENT_ID', IOS_CLIENT_ID);
assertCID('WEB_CLIENT_ID', WEB_CLIENT_ID);

console.log(`[BOOT v4.1] IOS_CLIENT_ID: ${IOS_CLIENT_ID.slice(0, 14)}...`);
console.log(`[BOOT v4.1] WEB_CLIENT_ID: ${WEB_CLIENT_ID.slice(0, 14)}...`);

const client = new OAuth2Client(WEB_CLIENT_ID);
const sessions = new Map(); // sessionId -> { userId, email, name, createdAt }

// בריאות/בדיקות
app.get('/', (req, res) => res.json({ status: 'OK', version: 'v4.1', at: new Date().toISOString() }));
app.get('/ok', (req, res) => res.type('text/plain').send('OK')); // <— זה ה"OK" שביקשת
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', version: 'v4.1', ts: Date.now() }));

// (לבדיקות בלבד, למחוק לפני פרודקשן)
app.get('/debug-config', (req, res) => {
  res.json({ ok: true, version: 'v4.1', ios: IOS_CLIENT_ID, web: WEB_CLIENT_ID });
});

// מקבל idToken מגוגל ומחזיר sessionId (האפליקציה תיצור Cookie ל-protilift.com)
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok:false, err:'missing token' });

    const ticket = await client.verifyIdToken({
      idToken,
      audience: [IOS_CLIENT_ID, WEB_CLIENT_ID],
    });
    const payload = ticket.getPayload();
    const userId = payload.sub;
    const email  = payload.email || null;
    const name   = payload.name  || null;

    const sessionId = `sess_${userId}_${Date.now()}`;
    sessions.set(sessionId, { userId, email, name, createdAt: Date.now() });

    return res.status(200).json({ ok: true, sessionId });
  } catch (err) {
    console.error('VERIFY ERROR:', err?.message || err);
    return res.status(401).json({ ok:false, err:String(err?.message || err) });
  }
});

// מי אני (בדיקות): מקבל sessionId ב-query/header/cookie
app.get('/whoami', (req, res) => {
  const sidFromQuery  = req.query.sessionId;
  const sidFromHeader = req.get('x-session-id');
  const sidFromCookie = (req.cookies && req.cookies.session) || null;
  const sid = sidFromQuery || sidFromHeader || sidFromCookie;

  if (!sid) return res.status(401).json({ ok:false, err:'no session provided' });

  const user = sessions.get(sid);
  if (!user) return res.status(401).json({ ok:false, err:'invalid session' });

  res.json({ ok:true, user });
});

// 404 ידידותי
app.use((req, res) => {
  res.status(404).json({ ok:false, err:'not found', path: req.path, version: 'v4.1' });
});

const PORT = process.env.PORT || 3000; // Railway מגדיר PORT דינמי
app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
