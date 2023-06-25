const jwt = require('jsonwebtoken');

function requireLogin(req, res, next) {
  const token = req.headers['authorization'];

  if (token) {
    try {
      jwt.verify(token, process.env.JWT_SECRET);
      next();
    } catch (error) {
      res.status(401).send('Unauthorized');
    }
  } else {
    res.status(401).send('Unauthorized');
  }
}

module.exports = {
  requireLogin
};
