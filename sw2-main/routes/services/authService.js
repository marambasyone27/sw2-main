// services/authService.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/users");

async function registerUser({ name, email, phone, password }) {
  const existingUser = await User.findOne({ email });
  if (existingUser) throw new Error("User already exists");

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, phone, password: hashedPassword });
  await newUser.save();
  return "User registered successfully";
}

async function loginUser({ email, password }) {
  const user = await User.findOne({ email });
  if (!user) throw new Error("User not found");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) throw new Error("Invalid credentials");

  if (email === process.env.ADMIN_EMAIL) {
    if (password !== process.env.ADMIN_PASS) {
      throw new Error("Invalid admin password");
    }

    const token = jwt.sign({ id: user._id, role: "admin" }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return { msg: "Admin login successful", token, userId: user._id, role: "admin" };
  }

  const token = jwt.sign({ id: user._id, role: "user" }, process.env.JWT_SECRET, { expiresIn: "1h" });
  return { msg: "Regular user login successful", token, userId: user._id, role: "user" };
}

module.exports = { registerUser, loginUser };
