// server.js – API פשוט לאימות Google ב-iOS
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// "מסד" זמני בזיכרון בשביל בדיקות
const sessions = new Map();

// בריאות/בדיקות
app.get('/ok', (req, res) => res.type('text').send('OK'));
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', ts: Date.now() }));

// אימות Google ל-iOS: מקבל idToken מאפליקציית iOS, מאמת מול IOS_CLIENT_ID
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok: false, err: 'missing idToken' });

    const IOS_CLIENT_ID = process.env.IOS_CLIENT_ID;
    if (!IOS_CLIENT_ID) return res.status(500).json({ ok: false, err: 'server missing IOS_CLIENT_ID' });

    const client = new OAuth2Client(); // לא חייבים clientId כאן
    const ticket = await client.verifyIdToken({ idToken, audience: IOS_CLIENT_ID });
    const payload = ticket.getPayload();

    // צור סשן זמני לבדיקות
    const sid = crypto.randomUUID();
    sessions.set(sid, { sub: payload.sub, email: payload.email, name: payload.name });

    // החזר קוקי סשן
    res.cookie(process.env.COOKIE_NAME || 'session', sid, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.COOKIE_SECURE === 'true',
      maxAge: 1000 * 60 * 60 * 24 * 7
    }).json({ ok: true });
  } catch (e) {
    console.error('verify error:', e?.message || e);
    res.status(401).json({ ok: false, err: e?.message || 'invalid token' });
  }
});

// בדיקת סשן (לא חובה לאישור לוגין, טוב לדיבאג)
app.get('/api/auth/session/validate', (req, res) => {
  const sid = req.cookies?.session;
  if (!sid) return res.status(401).json({ ok: false });
  const user = sessions.get(sid);
  if (!user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user });
});

// עזר דיבאג לראות אם יש קוקי
app.get('/whoami', (req, res) => {
  const sid = req.cookies?.session;
  res.json({ sid, hasCookie: !!sid });
});

// הפעלה
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
