// server.js — protilift pilot (version 3)
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

/* ====== שים כאן את ה-CLIENT IDs האמיתיים עם מרכאות! ====== */
// דוגמה לצורה הנכונה (תחליף לטקסטים שלך):
const IOS_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
const WEB_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
/* ========================================================= */

// בדיקות חכמות כדי לתפוס טעויות בפורמט / בלי מרכאות
function assertCID(name, value) {
  if (typeof value !== 'string') {
    throw new Error(`${name} must be a string (missing quotes?)`);
  }
  if (!value.includes('.apps.googleusercontent.com')) {
    throw new Error(`${name} looks wrong: ${value}`);
  }
}
assertCID('IOS_CLIENT_ID', IOS_CLIENT_ID);
assertCID('WEB_CLIENT_ID', WEB_CLIENT_ID);

// לוג פתיחה לזיהוי גרסה וערכים
console.log(`[BOOT v3] IOS_CLIENT_ID: ${IOS_CLIENT_ID.slice(0, 12)}...`);
console.log(`[BOOT v3] WEB_CLIENT_ID: ${WEB_CLIENT_ID.slice(0, 12)}...`);

const client = new OAuth2Client(WEB_CLIENT_ID);
const sessions = new Map();

// בריאות
app.get('/', (req, res) => res.json({ status: 'OK', at: new Date().toISOString(), version: 'v3' }));
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', ts: Date.now(), version: 'v3' }));

// דיבאג — חייב להחזיר את שני ה-IDs אחד לאחד
app.get('/debug-config', (req, res) => {
  res.json({
    ok: true,
    version: 'v3',
    ios: IOS_CLIENT_ID,
    web: WEB_CLIENT_ID
  });
});

// קבלת idToken מהאפליקציה
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok: false, err: 'missing token' });

    // אימות מול שני ה-audience (iOS + Web)
    const ticket = await client.verifyIdToken({
      idToken,
      audience: [IOS_CLIENT_ID, WEB_CLIENT_ID],
    });
    const payload = ticket.getPayload();
    const userId = payload.sub;
    const email = payload.email;
    const name = payload.name;

    const sessionId = `sess_${userId}_${Date.now()}`;
    sessions.set(sessionId, { userId, email, name, createdAt: Date.now() });

    return res.status(200).json({ ok: true, sessionId });
  } catch (err) {
    console.error('VERIFY ERROR:', err?.message || err);
    return res.status(401).json({ ok: false, err: String(err?.message || err) });
  }
});

// 404 ידידותי
app.use((req, res) => {
  res.status(404).json({ ok: false, err: 'not found', path: req.path, version: 'v3' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
