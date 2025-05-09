const jwt = require('jsonwebtoken');
require('dotenv').config();

const jwtMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', ''); // Get the token from the Authorization header
  if (!token) return res.status(401).json({ msg: "No token, authorization denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;  // Attach the decoded token to the request object
    next();
  } catch (error) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Forbidden' });
    }
    next();
  };
};

module.exports = { jwtMiddleware, authorize };
