// server.js
require('dotenv').config(); // optional — for local dev .env
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);

const app = express();

// Load DATABASE_URL from env
// Example DATABASE_URL: postgres://user:pass@host:5432/dbname
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // If using self-signed / require TLS you may need:
  // ssl: { rejectUnauthorized: false }
});

// (Optional) init table if not exists (simple migration)
async function ensureTables() {
  const create = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `;
  await pool.query(create);
}
ensureTables().catch(err => {
  console.error('Migration failed', err);
  process.exit(1);
});

// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Use pg-backed session store (persistent sessions)
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session' // defaults to 'session'
  }),
  secret: process.env.SESSION_SECRET || 'replace-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24*60*60*1000 } // 1 day
}));

// serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// helper: query user
async function findUserByEmail(email) {
  const res = await pool.query('SELECT id, email, password_hash, created_at FROM users WHERE email = $1', [email]);
  return res.rows[0];
}

// signup
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const existing = await findUserByEmail(email);
    if (existing) return res.status(409).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hash]
    );

    req.session.userId = insert.rows[0].id;
    req.session.email = insert.rows[0].email;

    res.json({ success: true, message: 'Account created', email: insert.rows[0].email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await findUserByEmail(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.userId = user.id;
    req.session.email = user.email;

    res.json({ success: true, message: 'Logged in', email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// protected profile
app.get('/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const r = await pool.query('SELECT id, email, created_at FROM users WHERE id = $1', [req.session.userId]);
  if (!r.rows[0]) return res.status(404).json({ error: 'User not found' });
  res.json({ user: r.rows[0] });
});

// logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Could not log out' });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
