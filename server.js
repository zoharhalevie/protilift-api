// server.js — Protilift API (Railway safe)

const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---- קונפיג ----
const PORT = process.env.PORT || 8080;
const IOS_CLIENT_ID = process.env.IOS_CLIENT_ID || '';
const WEB_CLIENT_ID = process.env.WEB_CLIENT_ID || '';

if (!IOS_CLIENT_ID) {
  console.warn('[WARN] IOS_CLIENT_ID is missing! /api/auth/google-idtoken will return 500 until you set it.');
}

const googleClient = new OAuth2Client({ clientId: IOS_CLIENT_ID || undefined });

// “מסד זמני” בזיכרון
const sessions = new Map();

// ---- בריאות/דיבוג ----
app.get('/ok', (req, res) => res.type('text/plain').send('OK'));
app.get('/hello', (req, res) => {
  res.json({
    ok: true,
    from: 'node',
    env: { hasIOS: !!IOS_CLIENT_ID, hasWEB: !!WEB_CLIENT_ID, port: PORT, node: process.version },
  });
});
app.get('/debug-config', (req, res) => {
  res.json({ ok: true, IOS_CLIENT_ID_present: !!IOS_CLIENT_ID, WEB_CLIENT_ID_present: !!WEB_CLIENT_ID, sessionsSize: sessions.size });
});
app.get('/whoami', (req, res) => {
  const fromCookie = req.cookies?.session || null;
  const fromHeader = req.get('x-session') || null;
  const fromQuery  = req.query.session || null;
  const sid = fromCookie || fromHeader || fromQuery || null;
  const user = sid ? sessions.get(sid) : null;
  res.json({ sid, fromHeader: !!fromHeader, fromQuery: !!fromQuery, hasCookie: !!fromCookie, loggedIn: !!user, user: user || null });
});
app.get('/api/auth/session/validate', (req, res) => {
  const sid = req.cookies?.session || req.get('x-session') || req.query.session;
  if (!sid) return res.status(401).json({ ok: false, err: 'no sid' });
  const user = sessions.get(sid);
  if (!user) return res.status(401).json({ ok: false, err: 'invalid sid' });
  res.json({ ok: true, user });
});

// ---- אימות Google IdToken מה-iOS ----
app.post('/api/auth/google-idtoken', async (req, res) => {
  try {
    if (!IOS_CLIENT_ID) return res.status(500).json({ ok: false, err: 'IOS_CLIENT_ID missing on server' });

    const idToken =
      req.body?.idToken ||
      req.get('x-id-token') ||
      (typeof req.body === 'string' ? req.body : '');

    if (!idToken) return res.status(400).json({ ok: false, err: 'missing idToken' });

    const ticket = await googleClient.verifyIdToken({ idToken, audience: IOS_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload) return res.status(401).json({ ok: false, err: 'no payload' });
    if (payload.aud && payload.aud !== IOS_CLIENT_ID)
      return res.status(401).json({ ok: false, err: 'Wrong recipient, payload.aud != IOS_CLIENT_ID' });

    const sid = `${payload.sub}.${Date.now()}`;
    const user = { sub: payload.sub, email: payload.email, name: payload.name || '', picture: payload.picture || '', provider: 'google' };
    sessions.set(sid, user);

    res.cookie('session', sid, { httpOnly: false, sameSite: 'Lax', secure: true, maxAge: 1000 * 60 * 60 * 24 * 7 });
    res.json({ ok: true, sid, user });
  } catch (err) {
    console.error('verify error:', err?.message || err);
    res.status(401).json({ ok: false, err: err?.message || 'verify failed' });
  }
});

// ---- האזנה ----
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on http://0.0.0.0:${PORT}`);
});

process.on('unhandledRejection', e => console.error('unhandledRejection', e));
process.on('uncaughtException', e => console.error('uncaughtException', e));
