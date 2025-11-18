// server.js — API ל-Protilift (לוגין iOS עם Google + יצירת session cookie)

const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ===== הגדרות בסיס =====

// דומיין של הקוקי (שיתאים לאתר שלך)
const COOKIE_DOMAIN = '.protilift.com';

// שם הקוקי (אפשר גם מה-ENV)
const COOKIE_NAME = process.env.COOKIE_NAME || 'pl_api_session';

// האם הקוקי ישלח רק ב-HTTPS (בפרודקשן כן)
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'false' ? false : true;

// תוקף הקוקי (שבוע)
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

// Client IDs של גוגל (כבר הגדרת ב-Railway)
const IOS_CLIENT_ID = process.env.IOS_CLIENT_ID;
const WEB_CLIENT_ID = process.env.WEB_CLIENT_ID;

// Secret לחתימה (תוסיף ב-Railway ENV: SESSION_SECRET עם ערך רנדומלי חזק)
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE_ME_SESSION_SECRET';

// מקורות שמותר להם לעבוד מול ה-API (CORS)
const ALLOWED_ORIGINS = new Set([
  'https://protilift.com',
  'https://www.protilift.com',
]);

// ===== CORS בסיסי =====
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

// ===== Google OAuth Client =====
const iosClient = new OAuth2Client(IOS_CLIENT_ID);

// ===== ראוט בריאות =====
app.get('/health', (req, res) => {
  res.send('ok');
});

// ===== לוגין מ-iOS =====
//
// האפליקציה טוענת ב-WebView:
//   https://api.protilift.com/ios/login?id_token=XXXXX
//
// כאן אנחנו מאמתים את ה-id_token, יוצרים session cookie,
// ואז עושים redirect ל-https://protilift.com
//
app.get('/ios/login', async (req, res) => {
  const idToken = req.query.id_token;

  if (!idToken) {
    return res.status(400).send('Missing id_token');
  }

  try {
    // אימות ה-id_token מול ה-iOS Client ID
    const ticket = await iosClient.verifyIdToken({
      idToken,
      audience: IOS_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // מזהה יוזר ייחודי של גוגל
    const userId = payload.sub;

    const sessionData = {
      uid: userId,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      provider: 'google',
      iat: Date.now(),
    };

    // חותמים על ה-session (חתימה פשוטה)
    const sessionJson = JSON.stringify(sessionData);
    const signature = crypto
      .createHmac('sha256', SESSION_SECRET)
      .update(sessionJson)
      .digest('hex');

    const cookieValue = Buffer.from(
      JSON.stringify({ s: sessionJson, sig: signature })
    ).toString('base64');

    // שומרים cookie לדומיין .protilift.com
    res.cookie(COOKIE_NAME, cookieValue, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
      domain: COOKIE_DOMAIN,
      maxAge: COOKIE_MAX_AGE,
    });

    // מפה נרצה שה-frontend יעלה כשהמשתמש כבר מחובר
    res.redirect('https://protilift.com');
  } catch (err) {
    console.error('Error in /ios/login:', err);
    return res.status(401).send('Invalid id_token');
  }
});

// ===== ראוט אופציונלי לבדיקה של session מצד האתר =====
app.get('/session', (req, res) => {
  const raw = req.cookies[COOKIE_NAME];

  if (!raw) {
    return res.status(401).json({ loggedIn: false });
  }

  try {
    const decoded = JSON.parse(
      Buffer.from(raw, 'base64').toString('utf8')
    );

    const { s, sig } = decoded;
    const expectedSig = crypto
      .createHmac('sha256', SESSION_SECRET)
      .update(s)
      .digest('hex');

    if (sig !== expectedSig) {
      return res.status(401).json({ loggedIn: false });
    }

    const session = JSON.parse(s);
    return res.json({ loggedIn: true, user: session });
  } catch (e) {
    console.error('Error reading session cookie:', e);
    return res.status(401).json({ loggedIn: false });
  }
});

// ===== הפעלת השרת =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Protilift API listening on port', PORT);
});
