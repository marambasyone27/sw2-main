const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const User = require("./models/users");
require("dotenv").config();

// Rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  statusCode: 429,
  message: { message: "Too many login attempts. Please try again later." }
});

// Register Route
router.post("/register", async (req, res) => {
  try {
    const { name, email, phone, password, gender } = req.body;

    if (!validator.isEmail(email) || /<script.?>.?<\/script>/gi.test(email)) {
      return res.status(400).json({ msg: "Invalid or malicious email" });
    }

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

    const role = email === process.env.ADMIN_EMAIL ? 'admin' : 'user';
    const token = jwt.sign({ id: user._id, role }, process.env.JWT_SECRET, { expiresIn: "1h" });

    return res.json({
      msg: `${role.charAt(0).toUpperCase() + role.slice(1)} login successful`,
      token,
      userId: user._id,
      role
    });
  } catch (error) {
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
