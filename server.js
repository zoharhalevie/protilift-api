// server.js – API לוגין לאפליקציית iOS
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ===== הגדרות בסיס =====
const ORIGIN = 'https://protilift.com';
const COOKIE_DOMAIN = '.protilift.com';
const COOKIE_NAME = 'session';
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 ימים

// CORS בסיסי עם Credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Origin', ORIGIN); // חשוב: לא "*"
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// "מסד" זמני בזיכרון לבטא (לא לפרודקשן)
const sessions = new Map();

function newSession(payload) {
  const id = crypto.randomUUID();
  sessions.set(id, { ...payload, createdAt: Date.now() });
  return id;
}

function setSessionCookie(res, sessionId) {
  res.cookie(COOKIE_NAME, sessionId, {
    domain: COOKIE_DOMAIN,   // <- חשוב: עובד לכל תתי-הדומיין של protilift.com
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'none',        // <- מאפשר שליחה בין api.<domain> ל-<domain>
    maxAge: COOKIE_MAX_AGE
  });
}

// ===== בריאות/בדיקות =====
app.get('/ok', (req, res) => res.type('text').send('OK'));
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', ts: Date.now() }));

// ===== Google Sign-In (iOS) =====
// נדרש משתנה סביבה IOS_CLIENT_ID (ה-iOS Client ID מה-Google Cloud)
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok: false, err: 'missing idToken' });

    const IOS_CLIENT_ID = process.env.IOS_CLIENT_ID;
    if (!IOS_CLIENT_ID) return res.status(500).json({ ok: false, err: 'server missing IOS_CLIENT_ID' });

    const client = new OAuth2Client();
    const ticket = await client.verifyIdToken({ idToken, audience: IOS_CLIENT_ID });
    const payload = ticket.getPayload(); // sub, email, name, picture...

    // כאן בדרך כלל יוצרים/מאתרים משתמש בבסיס הנתונים
    const sessionId = newSession({ provider: 'google', sub: payload.sub, email: payload.email });

    setSessionCookie(res, sessionId);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('google-idtoken error:', e?.message || e);
    return res.status(401).json({ ok: false, err: 'invalid idToken' });
  }
});

// ===== Apple Sign-In (אופציונלי; צריך אימות אמיתי בהמשך) =====
app.post('/api/auth/apple-idtoken', async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ ok: false, err: 'missing idToken' });

  // TODO: לאמת את ה-idToken של אפל (חתימות/מפתחות ציבוריים). לבטא בלבד:
  const sessionId = newSession({ provider: 'apple', sub: 'apple:' + crypto.randomUUID() });
  setSessionCookie(res, sessionId);
  return res.status(200).json({ ok: true });
});

// ===== לוגין ידני בסיסי (בטא בלבד! ללא אימות אמיתי) =====
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, err: 'missing credentials' });

  // בטא: כל זוג פרטים יוצר סשן. בפרודקשן – לא!
  const sessionId = newSession({ provider: 'password', username });
  setSessionCookie(res, sessionId);
  return res.status(200).json({ ok: true });
});

// ===== בדיקת סשן/התנתקות =====
app.get('/api/auth/whoami', (req, res) => {
  const sid = req.cookies?.[COOKIE_NAME];
  const data = sid ? sessions.get(sid) : null;
  return res.json({ ok: true, session: !!data, data });
});

app.post('/api/auth/logout', (req, res) => {
  const sid = req.cookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  res.clearCookie(COOKIE_NAME, { domain: COOKIE_DOMAIN, path: '/' });
  return res.json({ ok: true });
});

// ===== הפעלה =====
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log('API listening on :' + PORT);
});
