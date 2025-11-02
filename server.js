// server.js — protilift pilot (v5)
// תומך: Google (idToken), Apple (idToken — פיילוט, בלי אימות מלא), Email+Password (bcrypt)
// מחזיר sessionId ב-JSON; באפליקציה מייצרים Cookie ל-protilift.com

const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cookieParser());

// לוג לכל בקשה
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/* ====== החלף כאן לערכים האמיתיים שלך, עם מרכאות ====== */
const IOS_CLIENT_ID = "413679716774-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com";
const WEB_CLIENT_ID = "413679716774-YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY.apps.googleusercontent.com";
/* ====================================================== */

// בדיקת פורמט IDs
function assertCID(name, value) {
  if (typeof value !== 'string') throw new Error(`${name} must be a string (missing quotes?)`);
  if (!value.includes('.apps.googleusercontent.com')) throw new Error(`${name} looks wrong: ${value}`);
}
assertCID('IOS_CLIENT_ID', IOS_CLIENT_ID);
assertCID('WEB_CLIENT_ID', WEB_CLIENT_ID);

console.log(`[BOOT v5] IOS_CLIENT_ID: ${IOS_CLIENT_ID.slice(0, 14)}...`);
console.log(`[BOOT v5] WEB_CLIENT_ID: ${WEB_CLIENT_ID.slice(0, 14)}...`);

// זיכרון לפיילוט (במקום DB)
const client = new OAuth2Client(WEB_CLIENT_ID);
const sessions = new Map();      // sessionId -> { userId, email, name, provider, createdAt }
const usersByEmail = new Map();  // email -> { userId, email, name, passHash }

// utils
function newSession(user) {
  const sessionId = `sess_${user.userId}_${Date.now()}`;
  sessions.set(sessionId, { ...user, createdAt: Date.now() });
  return sessionId;
}

// בריאות/בדיקות
app.get('/', (req, res) => res.json({ status: 'OK', version: 'v5', at: new Date().toISOString() }));
app.get('/ok', (req, res) => res.type('text/plain').send('OK'));
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', version: 'v5', ts: Date.now() }));

// (בדיקות בלבד — מחק לפני פרוד)
app.get('/debug-config', (req, res) => {
  res.json({ ok: true, version: 'v5', ios: IOS_CLIENT_ID, web: WEB_CLIENT_ID, users: usersByEmail.size, sessions: sessions.size });
});

/* ---------------------- GOOGLE ---------------------- */
// מקבל idToken מגוגל ומחזיר sessionId
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok:false, err:'missing token' });

    const ticket = await client.verifyIdToken({
      idToken,
      audience: [IOS_CLIENT_ID, WEB_CLIENT_ID],
    });
    const payload = ticket.getPayload();
    const user = {
      userId: payload.sub,
      email: payload.email || null,
      name: payload.name || null,
      provider: 'google',
    };
    const sessionId = newSession(user);
    return res.status(200).json({ ok: true, sessionId });
  } catch (err) {
    console.error('GOOGLE VERIFY ERROR:', err?.message || err);
    return res.status(401).json({ ok:false, err:String(err?.message || err) });
  }
});

/* ---------------------- APPLE ----------------------- */
// פיילוט: מקבל idToken של Apple ומייצר סשן — בלי אימות חתימה מלא (לפרוד צריך לאמת מול public keys של Apple)
app.post('/api/auth/apple-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok:false, err:'missing token' });

    // ⚠️ לפיילוט — נחלץ רק את ה-Subject (sub) מתוך ה-JWT בצורה נאיבית:
    // פורמט JWT: header.payload.signature (Base64URL). ננסה לקרוא payload.
    const parts = String(idToken).split('.');
    if (parts.length < 2) throw new Error('invalid apple token');
    const payloadJson = Buffer.from(parts[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson);

    const user = {
      userId: payload.sub || `apple_${Date.now()}`,
      email: payload.email || null,
      name: null,
      provider: 'apple',
    };
    const sessionId = newSession(user);
    return res.status(200).json({ ok: true, sessionId });
  } catch (err) {
    console.error('APPLE PARSE ERROR:', err?.message || err);
    return res.status(401).json({ ok:false, err:String(err?.message || err) });
  }
});

/* ---------------- Email + Password ------------------ */
// הרשמה
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok:false, err:'missing email/password' });
    if (usersByEmail.has(email)) return res.status(409).json({ ok:false, err:'email exists' });

    const passHash = await bcrypt.hash(password, 10);
    const user = { userId: `local_${Date.now()}`, email, name: name || null, passHash, provider: 'local' };
    usersByEmail.set(email, user);
    const sessionId = newSession(user);
    return res.status(200).json({ ok:true, sessionId });
  } catch (err) {
    console.error('SIGNUP ERROR:', err?.message || err);
    return res.status(500).json({ ok:false, err:'signup failed' });
  }
});

// כניסה
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok:false, err:'missing email/password' });

    const user = usersByEmail.get(email);
    if (!user) return res.status(401).json({ ok:false, err:'bad credentials' });
    const ok = await bcrypt.compare(password, user.passHash);
    if (!ok) return res.status(401).json({ ok:false, err:'bad credentials' });

    const sessionId = newSession(user);
    return res.status(200).json({ ok:true, sessionId });
  } catch (err) {
    console.error('LOGIN ERROR:', err?.message || err);
    return res.status(500).json({ ok:false, err:'login failed' });
  }
});

/* --------------------- WHOAMI ----------------------- */
// בדיקות: אפשר להעביר sessionId ב-query/header/cookie
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
  res.status(404).json({ ok:false, err:'not found', path: req.path, version: 'v5' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
