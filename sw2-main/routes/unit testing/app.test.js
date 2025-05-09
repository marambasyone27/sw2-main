const mongoose = require('mongoose');

jest.spyOn(mongoose, 'connect').mockResolvedValue(); // 👈 لازم قبل استدعاء app.js

const request = require('supertest');
const app = require('../app'); // 👈 بعد الـ spy

describe('App Integration Tests', () => {
  it('should load root route and return HTML file', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
  });

 
});