const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser'); // Import the cookie-parser middleware

require('dotenv').config();

const app = express();
const port = 3301;

// Set the views directory and view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); // Add the cookie-parser middleware

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

        // Generate a JWT token
        const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Return the token in the response
        res.status(200).send('User registered successfully');
        res.status(200).json({ token: token });
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

// Logout route
app.post('/logout', authenticateToken, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
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

      // Retrieve tasks for the user from the database
      const tasksQuery = 'SELECT * FROM tasks WHERE user_id = ?';
      db.query(tasksQuery, [userId], (err, tasksResults) => {
        if (err) {
          console.error('Error retrieving tasks:', err);
          res.status(500).send('Error retrieving tasks');
          return;
        }

        res.render('profile', { user: user, tasks: tasksResults }); // Render the 'profile' view (profile.ejs) and pass the user and tasks data as parameters
      });
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).send('Unauthorized');
  }
});

app.get('/tasks', authenticateToken, (req, res) => {
  // Fetch tasks from the database
  db.query('SELECT * FROM tasks', (err, results) => {
    if (err) {
      console.error('Error fetching tasks:', err);
      res.status(500).send('Error fetching tasks');
      return;
    }

    const tasks = results.map((task) => ({
      task_id: task.task_id,
      task_name: task.task_name,
      task_description: task.task_description,
      task_createdAt: new Date(task.created_at)
    }));

    res.render('index', { tasks });
  });
});



// Update task route
app.get('/tasks/:taskId/edit', authenticateToken, (req, res) => {
  const taskId = req.params.taskId;

  // Retrieve task from the database
  const taskQuery = 'SELECT * FROM tasks WHERE task_id = ?';
  db.query(taskQuery, [taskId], (err, taskResults) => {
    if (err) {
      console.error('Error retrieving task:', err);
      res.status(500).send('Error retrieving task');
      return;
    }

    if (taskResults.length === 0) {
      res.status(404).send('Task not found');
      return;
    }

    const task = taskResults[0];

    res.render('edit-task', { task: task }); // Render the 'edit-task' view (edit-task.ejs) and pass the task data as a parameter
  });
});

// Update task route - POST request
app.post('/tasks/:taskId/edit', authenticateToken, (req, res) => {
  const taskId = req.params.taskId;
  const { task_name, task_description } = req.body;

  // Update task in the database
  const updateQuery = 'UPDATE tasks SET task_name = ?, task_description = ? WHERE task_id = ?';
  db.query(updateQuery, [task_name, task_description, taskId], (err, result) => {
    if (err) {
      console.error('Error updating task:', err);
      res.status(500).send('Error updating task');
      return;
    }

    res.redirect('/profile'); // Redirect back to the profile page
  });
});

// Delete task route
app.get('/tasks/:taskId/delete', authenticateToken, (req, res) => {
  const taskId = req.params.taskId;

  // Delete task from the database
  const deleteQuery = 'DELETE FROM tasks WHERE task_id = ?';
  db.query(deleteQuery, [taskId], (err, result) => {
    if (err) {
      console.error('Error deleting task:', err);
      res.status(500).send('Error deleting task');
      return;
    }

    res.redirect('/profile'); // Redirect back to the profile page
  });
});

// Add task route - GET request
app.get('/tasks/add', authenticateToken, (req, res) => {
  res.render('add-task'); // Render the 'add-task' view (add-task.ejs)
});

// Add task route - POST request
app.post('/tasks/add', authenticateToken, (req, res) => {
  const { task_name, task_description } = req.body;

  // Get the user ID from the token
  const token = req.cookies.token;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  // Insert task into the database
  const insertQuery = 'INSERT INTO tasks (task_name, task_description, user_id) VALUES (?, ?, ?)';
  db.query(insertQuery, [task_name, task_description, userId], (err, result) => {
    if (err) {
      console.error('Error adding task:', err);
      res.status(500).send('Error adding task');
      return;
    }

    res.redirect('/profile'); // Redirect back to the profile page
  });
});

// ...


// Save task route
app.post('/tasks', authenticateToken, (req, res) => {
  const { task_name, task_description } = req.body;

  // Get the user ID from the token
  const token = req.cookies.token;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  // Insert task into the database
  const insertQuery = 'INSERT INTO tasks (task_name, task_description, user_id) VALUES (?, ?, ?)';
  db.query(insertQuery, [task_name, task_description, userId], (err, result) => {
    if (err) {
      console.error('Error adding task:', err);
      res.status(500).send('Error adding task');
      return;
    }

    res.redirect('/profile'); // Redirect back to the profile page
  });
});

// Middleware to authenticate the JWT token
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something went wrong');
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
