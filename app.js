const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser'); 

require('dotenv').config();

const app = express();
const port = 5002;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); 
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
}));

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

        // Instead of sending a response with a token, redirect back to the same page
        res.redirect(req.get('referer'));
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

        // Store the token in the session
        req.session.token = token;
        res.redirect('/profile');
      } else {
        res.status(401).send('Invalid email or password');
      }
    });
  });
});

app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.userId;

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
});

function authenticateToken(req, res, next) {
  const token = req.session.token;

  if (!token) {
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
app.post('/logout', (req, res) => {
  // Clear the session token
  req.session.token = null;
  
  // Redirect the user to the homepage or any other desired page after logout
  res.redirect('/');
});


app.post("/addtask", (req, res) => {
  const { taskName, taskDescription, userId } = req.body;

  const checkUserQuery = `SELECT * FROM user WHERE id = ?`;
  db.query(checkUserQuery, [userId], (error, userResults) => {
    if (error) {
      console.error("Error checking user:", error);
      res.redirect("/"); 
    } else {
      if (userResults.length > 0) {
        const addTaskQuery = `INSERT INTO tasks (task_name, task_description, user_id) VALUES (?, ?, ?)`;
        db.query(addTaskQuery, [taskName, taskDescription, userId], (error, taskResults) => {
          if (error) {
            console.error("Error adding task:", error);
            res.redirect("/"); 
          } else {
            res.redirect("/");
          }
        });
      } else {
        console.error("User not found");
        res.redirect("/"); 
      }
    }
  });
});
app.post('/tasks/edit/:id', function(req, res, next) {
  const id = req.params.id;
  const taskName = req.body.task_name; // Get the updated task name from the request body
  const taskDescription = req.body.task_description; // Get the updated task description from the request body
  const taskTime = new Date(); // Replace with the updated task time

  var query = `UPDATE tasks SET task_name = ?, task_description = ?, task_updatedAt = ? WHERE task_id = ?`;
  db.query(query, [taskName, taskDescription, taskTime, id], function(err, result) {
    if (err) {
      console.error('Error updating task:', err);
      res.status(500).json({ error: 'Error updating task' });
    } else if (result.affectedRows === 0) {
      console.log('Task not found');
      res.status(404).json({ error: 'Task not found' });
    } else {
      console.log('Task updated:', result);
      res.json({ success: true });
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

    // Send a response indicating successful deletion
    res.status(200).send('Task deleted');
  });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something went wrong');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

       