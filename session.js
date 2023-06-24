// session.js

// Custom middleware to require login
const requireLogin = (req, res, next) => {
    if (req.session.userId) {
      next();
    } else {
      res.redirect('/login.html');
    }
  };
  
  module.exports = {
    requireLogin
  };
  