const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');

require('dotenv').config();

const app = express();
const port = 3000;

// Set the views directory and view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database configuration
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database');
});

// Register route
app.post('/register', (req, res) => {
  const { name, email, password, password_confirmation } = req.body;

  // Check if any of the required fields are empty
  if (!name || !email || !password || !password_confirmation) {
    res.status(400).send('All fields are required');
    return;
  }

  // Check if the password and password_confirmation match
  if (password !== password_confirmation) {
    res.status(400).send('Passwords do not match');
    return;
  }

  // Check if the email already exists
  const emailQuery = 'SELECT * FROM user WHERE email = ?';
  db.query(emailQuery, [email], (err, result) => {
    if (err) {
      console.error('Error checking email:', err);
      res.status(500).send('Error registering user');
      return;
    }

    if (result.length > 0) {
      // Email already exists, return an error
      res.status(400).send('Email already exists');
      return;
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error('Error hashing password:', err);
        res.status(500).send('Error registering user');
        return;
      }

      // Insert user into the database
      const insertQuery = 'INSERT INTO user (name, email, password) VALUES (?, ?, ?)';
      db.query(insertQuery, [name, email, hash], (err, result) => {
        if (err) {
          console.error('Error registering user:', err);
          res.status(500).send('Error registering user');
          return;
        }
        console.log('User registered:', result);
        res.status(200).send('User registered successfully');
      });
    });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Check if any of the required fields are empty
  if (!email || !password) {
    res.status(400).send('Email and password are required');
    return;
  }

  // Find the user by email
  const query = 'SELECT * FROM user WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error logging in:', err);
      res.status(500).send('Error logging in');
      return;
    }

    if (results.length === 0) {
      res.status(401).send('Invalid email or password');
      return;
    }

    const user = results[0];

    // Compare the password hash
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error('Error comparing passwords:', err);
        res.status(500).send('Error logging in');
        return;
      }

      if (result) {
        // Generate a JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Redirect to the profile page with the token as a query parameter
        res.redirect(`/profile?token=${token}`);
      } else {
        res.status(401).send('Invalid email or password');
      }
    });
  });
});

// Profile route
app.get('/profile', (req, res) => {
  const token = req.query.token;

  if (!token) {
    res.status(401).send('Unauthorized');
    return;
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    // Retrieve user data from the database
    const query = 'SELECT * FROM user WHERE id = ?';
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Error retrieving user data:', err);
        res.status(500).send('Error retrieving user data');
        return;
      }

      if (results.length === 0) {
        res.status(404).send('User not found');
        return;
      }

      const user = results[0];
      res.render('profile', { user: user }); // Render the 'profile' view (profile.ejs) and pass the user data as a parameter
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).send('Unauthorized');
  }
});


// Logout route
app.post('/logout', authenticateToken, (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'Logout successful' });
});


// Middleware to authenticate the JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    res.status(401).send('Unauthorized');
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Error verifying token:', err);
      res.status(403).send('Invalid token');
      return;
    }

    req.user = user;
    next();
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something went wrong' + err.message);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
