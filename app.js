const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
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
const sessionSecret = process.env.SESSION_SECRET || 'my_long_and_random_session_secret';
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: sessionSecret,
    resave: true,
    saveUninitialized: true
  })
);

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

// Custom middleware to require login
const requireLogin = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

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
        // Store the user ID in the session
        req.session.userId = user.id;
        res.redirect('/profile');
      } else {
        res.status(401).send('Invalid email or password');
      }
    });
  });
});

// Serve the profile page
app.get('/profile', requireLogin, (req, res) => {
  // Retrieve user data from the database
  const userId = req.session.userId;
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
});

// Logout route
app.post('/logout', requireLogin, (req, res) => {
  // Destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error('Error logging out:', err);
      res.status(500).send('Error logging out');
      return;
    }
    res.sendFile(path.join(__dirname, 'public', 'logout.html'));
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something went wrong' + err.message);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
