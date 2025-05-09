const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const User = require("./models/users");
const router = express.Router();
require("dotenv").config();

// Apply login rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many login attempts. Please try again later.",
  statusCode: 429
});

// Authorization middleware (for protected routes)
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Forbidden' });
    }
    next();
  };
};

// Register Route
router.post("/register", async (req, res) => {
  try {
    const { name, email, phone, password, gender } = req.body;

    // Email validation + XSS check
    if (!validator.isEmail(email) || /<script.?>.?<\/script>/gi.test(email)) {
      return res.status(400).json({ msg: "Invalid or malicious email" });
    }

    // Password strength validation
    if (
      password.length < 8 ||
      !/[A-Z]/.test(password) ||
      !/[a-z]/.test(password) ||
      !/[0-9]/.test(password) ||
      !/[!@#$%^&*]/.test(password)
    ) {
      return res.status(400).json({ msg: "Password is too weak" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      gender,
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ msg: "User registered successfully", token });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Login Route
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: String(email) });
    if (!user) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // Admin login logic
    if (email === process.env.ADMIN_EMAIL) {
      
      const token = jwt.sign({ id: user._id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: "1h" });
      return res.json({
        msg: "Admin login successful",
        token,
        userId: user._id,
        role: 'admin'
      });
    }

    // Regular user login
    const token = jwt.sign({ id: user._id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return res.json({
      msg: "Regular user login successful",
      token,
      userId: user._id,
      role: 'user'
    });
  } catch (error) {
    console.error("Login error: ", error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Middleware to verify JWT token
const jwtMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Invalid token' });
  }
};

// Protected route: Get user data by ID
router.get("/users/:id", jwtMiddleware, async (req, res) => {
  try {
    if (req.params.id !== req.user.id) {
      return res.status(403).json({ msg: "Unauthorized access" });
    }

    const userData = await User.findById(req.params.id).select('-password');
    if (!userData) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.json(userData);
  } catch (error) {
    console.error("Error fetching user data: ", error);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;