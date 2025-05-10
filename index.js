const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();
const path = require('path');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
    res.status(200).send('Signup successful');
  } catch (err) {
    res.status(500).send('Signup failed: ' + err.message);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user.id;
    res.redirect('/dashboard');
  } else {
    res.status(401).send('Invalid login');
  }
});

app.get('/dashboard', async (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.post('/update', async (req, res) => {
  if (!req.session.userId) return res.status(401).send('Unauthorized');
  const { details } = req.body;
  await pool.query('UPDATE users SET details = $1 WHERE id = $2', [details, req.session.userId]);
  res.send('Details updated');
});

app.get('/summary', async (req, res) => {
  if (!req.session.userId) return res.status(401).send('Unauthorized');
  const result = await pool.query('SELECT email, details FROM users WHERE id = $1', [req.session.userId]);
  res.json(result.rows[0]);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App running on port ${PORT}`));
