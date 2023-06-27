const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser'); 

require('dotenv').config();

const app = express();
const port = 4300;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); 

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database');
});

app.post('/register', (req, res) => {
  const { name, email, password, password_confirmation } = req.body;

  if (!name || !email || !password || !password_confirmation) {
    res.status(400).send('All fields are required');
    return;
  }

  if (password !== password_confirmation) {
    res.status(400).send('Passwords do not match');
    return;
  }

  const emailQuery = 'SELECT * FROM user WHERE email = ?';
  db.query(emailQuery, [email], (err, result) => {
    if (err) {
      console.error('Error checking email:', err);
      res.status(500).send('Error registering user');
      return;
    }

    if (result.length > 0) {
      res.status(400).send('Email already exists');
      return;
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error('Error hashing password:', err);
        res.status(500).send('Error registering user');
        return;
      }

      const insertQuery = 'INSERT INTO user (name, email, password) VALUES (?, ?, ?)';
      db.query(insertQuery, [name, email, hash], (err, result) => {
        if (err) {
          console.error('Error registering user:', err);
          res.status(500).send('Error registering user');
          return;
        }
        console.log('User registered:', result);

        const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ token: token });
      });
    });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).send('Email and password are required');
    return;
  }
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
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error('Error comparing passwords:', err);
        res.status(500).send('Error logging in');
        return;
      }

      if (result) {
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.redirect(`/profile?token=${token}`);
      } else {
        res.status(401).send('Invalid email or password');
      }
    });
  });
});

app.post('/logout', authenticateToken, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/profile', (req, res) => {
  const token = req.query.token;

  if (!token) {
    res.status(401).send('Unauthorized');
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const userQuery = 'SELECT * FROM user WHERE id = ?';
    db.query(userQuery, [userId], (err, userResults) => {
      if (err) {
        console.error('Error retrieving user data:', err);
        res.status(500).send('Error retrieving user data');
        return;
      }

      if (userResults.length === 0) {
        res.status(404).send('User not found');
        return;
      }

      const user = userResults[0];

      const tasksQuery = 'SELECT * FROM tasks WHERE user_id = ?';
      db.query(tasksQuery, [userId], (err, tasksResults) => {
        if (err) {
          console.error('Error retrieving tasks:', err);
          res.status(500).send('Error retrieving tasks');
          return;
        }

        res.render('profile', { user: user, tasks: tasksResults });  
      });
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).send('Invalid token');
  }
});



app.get('/tasks/edit/:id', function(req, res, next){
  const id = req.params.id;
  var query = `SELECT * FROM tasks WHERE id = "${id}"`;
  db.query(query, function(err, data){
    if(err){
      throw err;
    }
    else{
      res.redirect("/profile");
    }
  });
});

app.post('/tasks/delete/:id', function(req, res) {
  const taskId = req.params.id;
  
  // Delete the task from the database
  const query = 'DELETE FROM tasks WHERE task_id = ?';

  db.query(query, [taskId], function(err, result) {
    if (err) {
      console.error('Error deleting task:', err);
      res.status(500).send('Error deleting task');
      return;
    }

    if (result.affectedRows === 0) {
      console.log('Task not found');
      res.status(404).send('Task not found');
      return;
    }

    console.log('Task deleted:', result);
    res.sendStatus(200).redirect('/profile');
  });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    res.status(401).send('Unauthorized');
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Error verifying token:', err);
      res.status(403).send('Invalid token');
      return;
    }

    req.user = decoded;
    next();
  });
}

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something went wrong');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

       