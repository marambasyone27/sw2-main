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

    // Mock User.findOne to return null for new registrations
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

    // Mock successful user creation
    User.prototype.save.mockResolvedValue({
      _id: "123456",
      name: "Test User",
      email: "test@example.com",
      phone: "123456789",
      gender: "male"
    });

    // Mock User.findById with select chain
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
    // For registration, make sure User.findOne returns null
    User.findOne.mockResolvedValueOnce(null);
    
    const response = await request(app)
      .post("/auth/register")
      .send({
        name: "Test User",
        email: "newuser@example.com", // Use a different email than the mock
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

  test("Login with invalid credentials", async () => {
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
    expect(response.body).toHaveProperty("email", "test@example.com");
  });

  test("Access protected route with invalid token", async () => {
    jwt.verify = jest.fn().mockImplementation(() => {
      throw new Error("Invalid token");
    });

    const response = await request(app)
      .get("/auth/users/123456")
      .set("Authorization", "Bearer invalid_token");

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty("msg", "Invalid token");
  });

  test("Access protected route without token", async () => {
    const response = await request(app)
      .get("/auth/users/123456");

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty("msg", "No token provided"); // Updated to match actual response
  });
});