// server.js — Protilift API (Railway safe)
// יציב נגד נפילות: בודק env, מאזין ל־PORT של Railway, ולא זורק שגיאות לא מטופלות

const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---- קונפיג ----
const PORT = process.env.PORT || 8080;             // Railway מספק PORT
const 413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com = process.env.IOS_CLIENT_ID || '';
const 413679716774-eulnpt2b3l99qvs9j2erdo3lgdivf56r.apps.googleusercontent.com = process.env.WEB_CLIENT_ID || ''; // רשות

// לא להפיל את התהליך אם env חסר — רק נתריע בלוגים
if (!IOS_CLIENT_ID) {
  console.warn('[WARN] IOS_CLIENT_ID is missing! /api/auth/google-idtoken will return 500 until you set it.');
}

const googleClient = new OAuth2Client({
  clientId: IOS_CLIENT_ID || undefined,
});

// “מסד זמני” בזיכרון (Session Map)
const sessions = new Map();

// ---- בריאות/דיבוג ----
app.get('/ok', (req, res) => res.type('text/plain').send('OK'));

app.get('/hello', (req, res) => {
  res.json({
    ok: true,
    from: 'node',
    env: {
      hasIOS: !!IOS_CLIENT_ID,
      hasWEB: !!WEB_CLIENT_ID,
      port: PORT,
      node: process.version,
    },
  });
});

app.get('/debug-config', (req, res) => {
  res.json({
    ok: true,
    IOS_CLIENT_ID_present: !!IOS_CLIENT_ID,
    WEB_CLIENT_ID_present: !!WEB_CLIENT_ID,
    sessionsSize: sessions.size,
  });
});

// מי אני (ללא/עם sid בפרמטר/כותרת/קוקי)
app.get('/whoami', (req, res) => {
  const fromCookie = req.cookies?.session || null;
  const fromHeader = req.get('x-session') || null;
  const fromQuery  = req.query.session || null;
  const sid = fromCookie || fromHeader || fromQuery || null;
  const user = sid ? sessions.get(sid) : null;

  res.json({
    sid,
    fromHeader: !!fromHeader,
    fromQuery: !!fromQuery,
    hasCookie: !!fromCookie,
    loggedIn: !!user,
    user: user || null,
  });
});

// בדיקת סשן (שימושי לאפליקציה/ווב)
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
    if (!IOS_CLIENT_ID) {
      return res.status(500).json({ ok: false, err: 'IOS_CLIENT_ID missing on server' });
    }

    // נקבל את ה-idToken מגוף הבקשה או מכותרת
    const idToken =
      req.body?.idToken ||
      req.get('x-id-token') ||
      (typeof req.body === 'string' ? req.body : '');

    if (!idToken) {
      return res.status(400).json({ ok: false, err: 'missing idToken' });
    }

    // אימות הטוקן מול ה-audience של iOS
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: IOS_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload) {
      return res.status(401).json({ ok: false, err: 'no payload' });
    }

    // אפשר לדרוש גם aud == IOS_CLIENT_ID במפורש:
    if (payload.aud && payload.aud !== IOS_CLIENT_ID) {
      return res.status(401).json({ ok: false, err: 'Wrong recipient, payload.aud != IOS_CLIENT_ID' });
    }

    // יצירת sid ושמירת משתמש
    const sid = `${payload.sub}.${Date.now()}`;
    const user = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name || '',
      picture: payload.picture || '',
      provider: 'google',
    };
    sessions.set(sid, user);

    // קבע קוקי (רשות—נוח לווב)
    res.cookie('session', sid, {
      httpOnly: false,
      sameSite: 'Lax',
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 7, // שבוע
    });

    res.json({ ok: true, sid, user });
  } catch (err) {
    console.error('verify error:', err?.message || err);
    res.status(401).json({ ok: false, err: err?.message || 'verify failed' });
  }
});

// ---- האזנה (Railway) ----
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on http://0.0.0.0:${PORT}`);
});

// לא להפיל את התהליך על הבטחות לא מטופלות
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));
