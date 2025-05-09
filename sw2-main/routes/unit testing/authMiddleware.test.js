const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../app');  // تأكد من المسار الصحيح لتطبيقك

// تأكد من أنك قد قمت بتعريف هذه المتغيرات البيئية في .env
process.env.JWT_SECRET = 'your-secret-key';  // تأكد من أنك تستخدم السر الخاص بك

describe('JWT Middleware and Authorization Tests', () => {

  // اختبار jwtMiddleware
  describe('JWT Middleware', () => {

    it('should return 401 if no token is provided', async () => {
      const res = await request(app)
        .get('/api/protected')  // استبدل هذا بمسار محمي في تطبيقك
        .send();

      expect(res.status).toBe(401);
      expect(res.body.msg).toBe("No token, authorization denied");
    });

    it('should return 401 if an invalid token is provided', async () => {
      const res = await request(app)
        .get('/api/protected')  // استبدل هذا بمسار محمي في تطبيقك
        .set('Authorization', 'Bearer invalidtoken')
        .send();

      expect(res.status).toBe(401);
      expect(res.body.msg).toBe("Token is not valid");
    });

    it('should allow access if a valid token is provided', async () => {
      const payload = { id: '12345', role: 'user' };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      const res = await request(app)
        .get('/api/protected')  // استبدل هذا بمسار محمي في تطبيقك
        .set('Authorization', `Bearer ${token}`)
        .send();

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('msg', 'Access granted'); // تحقق من الرسالة المتوقعة من المسار المحمي
    });
  });

  // اختبار authorize
  describe('Authorize Middleware', () => {

    it('should return 403 if the user does not have the required role', async () => {
      const payload = { id: '12345', role: 'user' };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      const res = await request(app)
        .get('/api/admin')  // استبدل هذا بمسار محمي يتطلب الدور "admin"
        .set('Authorization', `Bearer ${token}`)
        .send();

      expect(res.status).toBe(403);
      expect(res.body.msg).toBe('Forbidden');
    });

    it('should allow access if the user has the required role', async () => {
      const payload = { id: '12345', role: 'admin' };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      const res = await request(app)
        .get('/api/admin')  // استبدل هذا بمسار محمي يتطلب الدور "admin"
        .set('Authorization', `Bearer ${token}`)
        .send();

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('msg', 'Admin access granted'); // تحقق من الرسالة المتوقعة من المسار المحمي
    });
  });
});
