const request = require('supertest');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('../app');
const User = require('../models/users');
require('dotenv').config();

jest.setTimeout(170000);

beforeAll(async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }

  await mongoose.connect(process.env.TEST_DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
});

afterAll(async () => {
  await mongoose.disconnect();
});

beforeEach(async () => {
  await User.deleteMany({});
});

describe('Security Tests', () => {
  let token, userId;

  beforeEach(async () => {
    const hashedPassword = await bcrypt.hash('StrongPass123!', 10);
    const user = await User.create({
      name: 'Maryyy',
      email: 'secureuser@example.com',
      phone: '01000000000',
      password: hashedPassword,
      gender: 'male'
    });

    userId = user._id.toString();
    token = jwt.sign({ id: userId }, process.env.JWT_SECRET || 'defaultsecret');
  });

  it('should prevent XSS in email field during signup', async () => {
    const res = await request(app).post('/api/auth/register').send({
      name: 'Script',
      email: '<script>alert(1)</script>@test.com',
      phone: '01111111111',
      password: 'StrongPass123!',
      confirmPassword: 'StrongPass123!',
      gender: 'female'
    });
    expect(res.statusCode).toBe(400);
  });

  it('should reject weak passwords during signup', async () => {
    const res = await request(app).post('/api/auth/register').send({
      name: 'Password',
      email: 'weakpass@example.com',
      phone: '01234567890',
      password: '123',
      confirmPassword: '123',
      gender: 'female'
    });
    expect(res.statusCode).toBe(400);
  });

  it('should not reveal if email exists during login', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'nonexisting@example.com',
      password: 'StrongPass123!'
    });
    expect(res.body.msg).toBe('Invalid credentials');
  });

  it('should prevent unauthorized user from accessing another user\'s data', async () => {
    const testUser = await User.create({
      name: 'Test User',
      email: 'unauthorized@example.com',
      phone: '01000000001',
      password: await bcrypt.hash('password123', 10),
      gender: 'male'
    });

    const hackerToken = jwt.sign(
      { id: 'fakeUserId', role: 'user' },
      process.env.JWT_SECRET || 'defaultsecret',
      { expiresIn: '1h' }
    );

    const res = await request(app)
      .get(`/api/auth/users/${testUser._id}`)
      .set('Authorization', `Bearer ${hackerToken}`);

    expect(res.statusCode).toBe(403);
    expect(res.body.msg).toBe('Unauthorized access');
  });

  it('should reject NoSQL injection attempt on login', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: { "$gt": "" },
      password: "any"
    });
    expect(res.statusCode).toBe(400);
  });

  it('should limit repeated failed login attempts', async () => {
    for (let i = 0; i < 6; i++) {
      await request(app).post('/api/auth/login').send({
        email: 'secureuser@example.com',
        password: 'WrongPassword'
      });
    }

    const res = await request(app).post('/api/auth/login').send({
      email: 'secureuser@example.com',
      password: 'WrongPassword'
    });

    expect(res.statusCode).toBe(429);
  });
});
