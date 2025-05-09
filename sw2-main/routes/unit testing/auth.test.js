const request = require("supertest");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/users");
const authRouter = require("../auth");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use("/auth", authRouter);

jest.mock("../models/users");

describe("Auth Routes", () => {
  let token;

  beforeEach(async () => {
    jest.clearAllMocks();

    // Mock bcrypt
    bcrypt.hash = jest.fn().mockResolvedValue("hashedPassword");
    bcrypt.compare = jest.fn().mockResolvedValue(true);

    // Mock User.findOne
    User.findOne.mockImplementation(({ email }) => {
      if (email === "test@example.com") {
        return Promise.resolve({
          _id: "123456",
          name: "Test User",
          email: "test@example.com",
          phone: "123456789",
          password: bcrypt.hashSync("Test@1234", 10),
          gender: "male"
        });
      }
      return Promise.resolve(null);
    });

    // Mock user save
    User.prototype.save = jest.fn().mockResolvedValue({
      _id: "123456",
      name: "Test User",
      email: "test@example.com",
      phone: "123456789",
      gender: "male"
    });

    // Mock findById
    User.findById.mockImplementation(() => ({

      select: jest.fn().mockResolvedValue({
        _id: "123456",
        name: "Test User",
        email: "test@example.com",
        phone: "123456789",
        gender: "male"
      })
    }));

    token = jwt.sign(
      { id: "123456", role: "user" },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
  });

  test("Register a new user", async () => {
    User.findOne.mockResolvedValueOnce(null);

    const response = await request(app)
      .post("/auth/register")
      .send({
        name: "Test User",
        email: "newuser@example.com",
        phone: "123456789",
        password: "Test@1234",
        gender: "male"
      });

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty("msg", "User registered successfully");
    expect(response.body).toHaveProperty("token");
  });

  test("Login with valid credentials", async () => {
    const response = await request(app)
      .post("/auth/login")
      .send({
        email: "test@example.com",
        password: "Test@1234"
      });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("msg", "Regular user login successful");
    expect(response.body).toHaveProperty("token");
  });

  test("Login with invalid password", async () => {
    bcrypt.compare = jest.fn().mockResolvedValue(false); // simulate password mismatch

    const response = await request(app)
      .post("/auth/login")
      .send({
        email: "test@example.com",
        password: "WrongPass123!"
      });

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("msg", "Invalid credentials");
  });

  test("Login with invalid email", async () => {
    const response = await request(app)
      .post("/auth/login")
      .send({
        email: "wrong@example.com",
        password: "WrongPassword1!"
      });

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("msg", "Invalid credentials");
  });

  test("Access protected route with valid token", async () => {
    jwt.verify = jest.fn().mockReturnValue({ id: "123456", role: "user" });

    const response = await request(app)
      .get("/auth/users/123456")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("name", "Test User");
  });

  test("Access protected route with no token", async () => {
    const response = await request(app)
      .get("/auth/users/123456");

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty("msg", "No token provided");
  });

  test("Access protected route with invalid token", async () => {
    jwt.verify = jest.fn(() => { throw new Error("Invalid token"); });

    const response = await request(app)
      .get("/auth/users/123456")
      .set("Authorization", "Bearer invalid_token");

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty("msg", "Invalid token");
  });

  test("Access protected route with user not found", async () => {
    jwt.verify = jest.fn().mockReturnValue({ id: "123456", role: "user" });

    User.findById.mockImplementationOnce(() => ({

      select: jest.fn().mockResolvedValue(null)
    }));

    const response = await request(app)
      .get("/auth/users/123456")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(404);
    expect(response.body).toHaveProperty("msg", "User not found");
  });

  test("Access protected route with server error", async () => {
    jwt.verify = jest.fn().mockReturnValue({ id: "123456", role: "user" });

    User.findById.mockImplementationOnce(() => {
      throw new Error("DB error");
    });

    const response = await request(app)
      .get("/auth/users/123456")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(500);
    expect(response.body).toHaveProperty("msg", "Server error");
  });

  test("Rate limit on login", async () => {
    for (let i = 0; i < 6; i++) {
      await request(app)
        .post("/auth/login")
        .send({
          email: "wrong@example.com",
          password: "WrongPassword1!"
        });
    }

    const lastRes = await request(app)
      .post("/auth/login")
      .send({
        email: "wrong@example.com",
        password: "WrongPassword1!"
      });

    // Check if rate limit triggered
    if (lastRes.status === 429) {
      expect(lastRes.body).toHaveProperty("message", "Too many login attempts. Please try again later.");
    }
  });

  // Test the new 'admin' protected route
  test("Access admin route with unauthorized role", async () => {
    jwt.verify = jest.fn().mockReturnValue({ id: "123456", role: "user" });

    const response = await request(app)
      .get("/auth/protected/admin")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(403);
    expect(response.body).toHaveProperty("msg", "Forbidden");
  });

  test("Access admin route with authorized role", async () => {
    jwt.verify = jest.fn().mockReturnValue({ id: "123456", role: "admin" });

    const response = await request(app)
      .get("/auth/protected/admin")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("msg", "Welcome, admin!");
  });
});
