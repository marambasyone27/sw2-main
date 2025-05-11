// unit testing/app.test.js
const { jwtMiddleware, authorize } = require('../middlewares/authMiddleware');
const jwt = require('jsonwebtoken');

jest.mock('jsonwebtoken');  // محاكاة مكتبة jwt

describe('JWT Middleware Unit Tests', () => {

  let mockNext;
  let mockRes;

  beforeEach(() => {
    mockNext = jest.fn();  // محاكاة دالة next
    mockRes = { status: jest.fn().mockReturnThis(), send: jest.fn(), json: jest.fn() };  // محاكاة استجابة Express
  });

  it('should call next() if token is valid', () => {
    const req = { headers: { authorization: 'Bearer valid_token' } }; // تعديل هنا
    // محاكاة سلوك jwt.verify
    jwt.verify.mockReturnValue({ id: '123', role: 'user' });

    jwtMiddleware(req, mockRes, mockNext);  // استدعاء الميدلوير
    expect(mockNext).toHaveBeenCalled();  // تأكد من أنه تم استدعاء next()
  });

  it('should send 401 if no token is provided', () => {
    const req = { headers: {} };  // لا يوجد توكن في الطلب

    jwtMiddleware(req, mockRes, mockNext);  // استدعاء الميدلوير
    expect(mockRes.status).toHaveBeenCalledWith(401);  // تأكد من إرسال 401
    expect(mockRes.json).toHaveBeenCalledWith({ msg: 'No token, authorization denied' });  // تأكد من الرسالة المرسلة
  });

  it('should send 401 if token is invalid', () => {
    const req = { headers: { authorization: 'Bearer invalid_token' } }; // تعديل هنا
    
    // محاكاة خطأ في التحقق من التوكن
    jwt.verify.mockImplementation(() => { throw new Error('Invalid token'); });

    jwtMiddleware(req, mockRes, mockNext);  // استدعاء الميدلوير
    expect(mockRes.status).toHaveBeenCalledWith(401);  // تأكد من إرسال 401
    expect(mockRes.json).toHaveBeenCalledWith({ msg: 'Token is not valid' });  // تأكد من الرسالة المرسلة
  });

});
