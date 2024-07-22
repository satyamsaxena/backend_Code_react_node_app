const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root', 
  password: '', 
  database: 'usersdb_backend', 
});

db.connect((err) => {
  if (err) throw err;
  console.log('MySQL connected...');
});

// Signup Route endpoint
app.post('/api/signup', (req, res) => {
  const { email, password, name } = req.body;

  // Check if email already exists
  const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailSql, [email], (err, results) => {
    if (err) return res.status(500).send('Error checking email');
    if (results.length > 0) return res.status(400).send('Email already registered');

    // Proceed with registration if email is unique
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).send('Error hashing password');

      const insertUserSql = 'INSERT INTO users (email, password, name) VALUES (?, ?, ?)';
      db.query(insertUserSql, [email, hashedPassword, name], (err) => {
        if (err) return res.status(500).send('Something went wrong!');
        res.status(200).send('User registered successfully');
      });
    });
  });
});

// Login Route endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';

  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).send('Error fetching user');
    if (results.length === 0) return res.status(400).send('User not found');

    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).send('Error comparing passwords');
      if (!isMatch) return res.status(400).send('Invalid credentials');

      const token = jwt.sign({ id: user.id }, 'your_jwt_secret', { expiresIn: '1h' });
      res.status(200).json({ message: 'Login successful', token, redirectUrl: '/dashboard' });
    });
  });
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('No token provided');

  jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
    if (err) return res.status(401).send('Invalid token');
    req.user = decoded;
    next();
  });
};

// User details endpoint
app.get('/api/user', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const sql = 'SELECT * FROM users WHERE id = ?';

  db.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).send('Error fetching user');
    if (results.length === 0) return res.status(404).send('User not found');

    res.json(results[0]);
  });
});

// Get all items
app.get('/api/items', (req, res) => {
  const query = 'SELECT * FROM items';
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// Get item by ID
app.get('/api/items/:id', (req, res) => {
  const query = 'SELECT * FROM items WHERE id = ?';
  db.query(query, [req.params.id], (err, results) => {
    if (err) throw err;
    res.json(results[0]);
  });
});

// Create new item
app.post('/api/items', (req, res) => {
  const { name, description, price, quantity } = req.body;
  const query = 'INSERT INTO items (name, description, price, quantity) VALUES (?, ?, ?, ?)';
  db.query(query, [name, description, price, quantity], (err, results) => {
    if (err) throw err;
    res.status(201).json({ id: results.insertId, name, description, price, quantity });
  });
});

// Update item
app.put('/api/items/:id', (req, res) => {
  const { name, description, price, quantity } = req.body;
  const query = 'UPDATE items SET name = ?, description = ?, price = ?, quantity = ? WHERE id = ?';
  db.query(query, [name, description, price, quantity, req.params.id], (err, results) => {
    if (err) throw err;
    res.json({ id: req.params.id, name, description, price, quantity });
  });
});

// Delete item
app.delete('/api/items/:id', (req, res) => {
  const query = 'DELETE FROM items WHERE id = ?';
  db.query(query, [req.params.id], (err, results) => {
    if (err) throw err;
    res.status(204).end();
  });
});

// Add to cart
app.post('/api/cart', authenticateToken, (req, res) => {
  const { itemId, quantity } = req.body;
  const userId = req.user.id;

  const query = 'INSERT INTO carts (user_id, item_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?';
  db.query(query, [userId, itemId, quantity, quantity], (err, results) => {
    if (err) return res.status(500).send('Error adding item to cart');
    res.json({ message: 'Item added to cart' });
  });
});

// Get cart items
app.get('/api/cart', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = 'SELECT items.*, carts.quantity FROM carts JOIN items ON carts.item_id = items.id WHERE carts.user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).send('Error fetching cart items');
    res.json(results);
  });
});

// Delete cart item
app.delete('/api/cart/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const itemId = req.params.id;

  const query = 'DELETE FROM carts WHERE user_id = ? AND item_id = ?';
  db.query(query, [userId, itemId], (err, results) => {
    if (err) return res.status(500).send('Error deleting cart item');
    res.status(204).end();
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
