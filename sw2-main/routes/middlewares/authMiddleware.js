const jwt = require('jsonwebtoken');

// JWT Middleware
const jwtMiddleware = (req, res, next) => {
  const token = req.headers['authorization']?.replace('Bearer ', ''); // Get the token from the Authorization header

  if (!token) return res.status(401).json({ msg: "No token, authorization denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token
    req.user = decoded;
    next(); // Call next if token is valid
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

// Authorize Middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Forbidden' }); // Forbidden if the role does not match
    }
    next();
  };
};

module.exports = { jwtMiddleware, authorize };
