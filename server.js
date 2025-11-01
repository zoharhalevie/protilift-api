// server.js — Railway pilot: מחזיר sessionId ב-JSON (iOS ייצור Cookie)
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cookieParser());

// לוג
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/* === החלף לערכים האמיתיים שלך (עם מרכאות מלאות) === */
const IOS_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
const WEB_CLIENT_ID = "413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com";
/* ==================================================== */

const client = new OAuth2Client(WEB_CLIENT_ID);
const sessions = new Map(); // sessionId -> user

app.get('/', (req, res) => res.json({ status: 'OK', at: new Date().toISOString() }));
app.get('/hello', (req, res) => res.json({ ok: true, from: 'node', ts: Date.now() }));

// אימות Google ID token
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ ok:false, err:'missing token' });

    const ticket = await client.verifyIdToken({
      idToken,
      audience: [413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com, 413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com],
    });
    const payload = ticket.getPayload();
    const userId = payload.sub, email = payload.email, name = payload.name;

    const sessionId = `sess_${userId}_${Date.now()}`;
    sessions.set(sessionId, { userId, email, name, createdAt: Date.now() });

    // חשוב: בפיילוט Railway לא מחזירים Set-Cookie (דומיין אחר),
    // מחזירים JSON עם sessionId — והאפליקציה תיצור עוגיה ל-protilift.com.
    return res.status(200).json({ ok: true, sessionId });
  } catch (err) {
    console.error('VERIFY ERROR:', err?.message || err);
    return res.status(401).json({ ok:false, err:String(err?.message || err) });
  }
});

// בדיקת סשן (רק לצורך בדיקה; כאן לא משתמשים ב-Cookie כי אנחנו בפיילוט)
app.get('/api/whoami', (req, res) => {
  const { sessionId } = req.query;
  const u = sessionId ? sessions.get(sessionId) : null;
  if (!u) return res.status(401).json({ ok:false });
  res.json({ ok:true, user:u });
});

const PORT = process.env.PORT || 3000; // Railway יזריק PORT
app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
