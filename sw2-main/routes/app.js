const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const authRoutes = require("./auth");
const { jwtMiddleware, authorize } = require('./middlewares/authMiddleware');

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// MongoDB Connection
mongoose.connect(process.env.CONNECT_DB)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(`MongoDB Error: ${err}`));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/cart", require("./cartRoute"));
app.use("/api/products", require("./product"));

app.get('/api/protected', jwtMiddleware, (req, res) => {
  res.json({ msg: 'Access granted' });
});

app.get('/api/admin', jwtMiddleware, authorize(['admin']), (req, res) => {
  res.json({ msg: 'Admin access granted' });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

module.exports = app;
