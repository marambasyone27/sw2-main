const jwt = require('jsonwebtoken');
const { jwtMiddleware, authorize } = require('../middlewares/authMiddleware');

// Mock JWT library
jest.mock('jsonwebtoken');

// Mock token in environment
process.env.JWT_SECRET = 'your-secret-key';

describe('JWT Middleware and Authorization Unit Tests', () => {

  describe('JWT Middleware', () => {

    it('should call next() if token is valid', () => {
      const req = {
        headers: { authorization: 'Bearer valid_token' } // Mock the headers
      };

      // Mock token validation
      jwt.verify.mockReturnValue({ id: '123', role: 'user' });

      const next = jest.fn();
      const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };

      jwtMiddleware(req, res, next);
      expect(next).toHaveBeenCalled();  // Ensure next() is called
    });

    it('should send 401 if no token is provided', () => {
      const req = { headers: { authorization: undefined } };  // No token
      const next = jest.fn();
      const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };

      jwtMiddleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);  // Ensure 401 is returned
      expect(res.json).toHaveBeenCalledWith({ msg: 'No token, authorization denied' });  // Ensure message is returned
    });

    it('should send 401 if token is invalid', () => {
      const req = {
        headers: { authorization: 'Bearer invalid_token' }  // Mock the invalid token
      };

      // Mock invalid token verification
      jwt.verify.mockImplementation(() => { throw new Error('Invalid token'); });

      const next = jest.fn();
      const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };

      jwtMiddleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);  // Ensure 401 is returned
      expect(res.json).toHaveBeenCalledWith({ msg: 'Token is not valid' });  // Ensure message is returned
    });

  });

  describe('Authorize Middleware', () => {
    it('should return 403 if user does not have required role', () => {
      const req = {
        user: { role: 'user' }  // Mock user role
      };
      const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
      const next = jest.fn();

      authorize(['admin'])(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);  // Ensure 403 is returned
      expect(res.json).toHaveBeenCalledWith({ msg: 'Forbidden' });  // Ensure message is returned
    });

    it('should call next() if user has required role', () => {
      const req = {
        user: { role: 'admin' }  // Mock user with required role
      };
      const res = {};
      const next = jest.fn();

      authorize(['admin'])(req, res, next);
      expect(next).toHaveBeenCalled();  // Ensure next() is called
    });
  });

});
