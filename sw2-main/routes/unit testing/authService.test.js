const { registerUser, loginUser } = require("../services/authService");
const User = require("../models/users");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

jest.mock("../models/users");
jest.mock("bcryptjs");
jest.mock("jsonwebtoken");

describe("Auth Service", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("registerUser", () => {
    it("should throw if user already exists", async () => {
      User.findOne.mockResolvedValue(true);
      await expect(registerUser({ email: "test@example.com" }))
        .rejects.toThrow("User already exists");
    });

    it("should register a new user", async () => {
      User.findOne.mockResolvedValue(null);
      bcrypt.hash.mockResolvedValue("hashedPass");
      const saveMock = jest.fn();
      User.mockImplementation(() => ({ save: saveMock }));

      const msg = await registerUser({
        name: "Test",
        email: "test@example.com",
        phone: "123456",
        password: "password123"
      });

      expect(msg).toBe("User registered successfully");
      expect(saveMock).toHaveBeenCalled();
    });
  });

  describe("loginUser", () => {
    beforeEach(() => {
      process.env.JWT_SECRET = "testsecret";
      process.env.ADMIN_EMAIL = "admin@test.com";
      process.env.ADMIN_PASS = "admin123";
    });

    it("should throw if user not found", async () => {
      User.findOne.mockResolvedValue(null);
      await expect(loginUser({ email: "no@user.com", password: "123" }))
        .rejects.toThrow("User not found");
    });

    it("should throw if password is incorrect", async () => {
      User.findOne.mockResolvedValue({ password: "hashed" });
      bcrypt.compare.mockResolvedValue(false);

      await expect(loginUser({ email: "user@test.com", password: "wrong" }))
        .rejects.toThrow("Invalid credentials");
    });

    it("should throw if admin password is incorrect", async () => {
      const user = { _id: "123", password: "hashed" };
      User.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);

      await expect(loginUser({ email: "admin@test.com", password: "wrongadmin" }))
        .rejects.toThrow("Invalid admin password");
    });

    it("should login admin successfully", async () => {
      const user = { _id: "adminId", password: "adminHashed" };
      User.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);
      jwt.sign.mockReturnValue("adminToken");

      const result = await loginUser({ email: "admin@test.com", password: "admin123" });

      expect(result).toEqual({
        msg: "Admin login successful",
        token: "adminToken",
        userId: "adminId",
        role: "admin"
      });
    });

    it("should login regular user successfully", async () => {
      const user = { _id: "userId", password: "hashed" };
      User.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);
      jwt.sign.mockReturnValue("userToken");

      const result = await loginUser({ email: "user@test.com", password: "password123" });

      expect(result).toEqual({
        msg: "Regular user login successful",
        token: "userToken",
        userId: "userId",
        role: "user"
      });
    });
  });
});
