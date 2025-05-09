const request = require("supertest");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/users");
const router = require("../auth");

const app = express();
app.use(express.json());
app.use("/api", router);

jest.mock("../models/users");

describe("Auth Routes Unit Tests", () => {
  
  // ✅ Test email validation
  test("Should reject registration with an invalid email", async () => {
    const res = await request(app).post("/api/register").send({
      name: "Test User",
      email: "invalid-email",
      phone: "0123456789",
      password: "SecureP@ss123",
      gender: "male"
    });
    expect(res.status).toBe(400);
    expect(res.body.msg).toBe("Invalid or malicious email");
  });

  // ✅ Test duplicate user registration
  test("Should reject registration if user already exists", async () => {
    User.findOne.mockResolvedValue({ email: "test@example.com" });
    const res = await request(app).post("/api/register").send({
      name: "Test User",
      email: "test@example.com",
      phone: "0123456789",
      password: "SecureP@ss123",
      gender: "male"
    });
    expect(res.status).toBe(400);
    expect(res.body.msg).toBe("User already exists");
  });

  // ✅ Test incorrect password during login
  test("Should reject login with incorrect password", async () => {
    User.findOne.mockResolvedValue({
      email: "test@example.com",
      password: await bcrypt.hash("CorrectPass123", 10)
    });

    const res = await request(app).post("/api/login").send({
      email: "test@example.com",
      password: "WrongPass123"
    });

    expect(res.status).toBe(400);
    expect(res.body.msg).toBe("Invalid credentials");
  });

  // ✅ Test missing authentication token
  test("Should reject access to user data without a token", async () => {
    const res = await request(app).get("/api/users/12345");
    expect(res.status).toBe(401);
    expect(res.body.msg).toBe("No token provided");
  });

  test("Should reject access to another user's data", async () => {
    const token = jwt.sign({ id: "67890" }, "test-secret", { expiresIn: "1h" });

    const res = await request(app)
      .get("/api/users/12345")
      .set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(401);
    expect(res.body.msg).toBe("Invalid token");
  });

});
