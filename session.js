// Custom middleware to require login
const requireLogin = (req, res, next) => {
  const token = req.headers['authorization'];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded.user;
      next();
    } catch (error) {
      res.redirect('/index.html');
    }
  } else {
    res.redirect('/index.html');
  }
};

module.exports = {
  requireLogin
};
