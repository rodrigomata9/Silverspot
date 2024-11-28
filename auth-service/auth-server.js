const express = require('express');
const mysql = require('mysql2');
const argon2 = require('argon2'); // Use Argon2 for password hashing
const jwt = require('jsonwebtoken'); // Generate tokens for verifying users

// Set up express
const app = express();
app.use(express.json());

// Connect to MySQL Database
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'your_password',
  database: 'silverspot_cinema',
});

const secretKey = 'your_secret_key'; // Replace with a secure key

// User Registration
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  try {
    const hashedPassword = await argon2.hash(password); // Hash the password with Argon2
    const query = 'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)';
    pool.query(query, [username, hashedPassword, email], (err, results) => {
      if (err) return res.status(500).send(err);
      res.status(201).send({ message: 'User registered successfully!' });
    });
  } catch (err) {
    res.status(500).send({ message: 'Error hashing password', error: err });
  }
});

// User Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ?';
  pool.query(query, [username], async (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).send({ message: 'User not found' });

    const user = results[0];
    try {
      const isMatch = await argon2.verify(user.password_hash, password); // Verify password with Argon2
      if (!isMatch) return res.status(401).send({ message: 'Invalid credentials' });

      const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
      res.send({ message: 'Login successful', token });
    } catch (err) {
      res.status(500).send({ message: 'Error verifying password', error: err });
    }
  });
});

// Middleware to Verify Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Protected Route Example
app.get('/profile', authenticateToken, (req, res) => {
  res.send({ message: 'This is a protected route', user: req.user });
});

app.listen(3000, () => console.log('Auth service running on port 3000'));
