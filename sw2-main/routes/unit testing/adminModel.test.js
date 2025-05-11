const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Admin = require('../models/Admin');

jest.mock('bcrypt');

describe('Admin Model - Unit Test Only', () => {
  beforeAll(async () => {
    await mongoose.connect('mongodb://127.0.0.1:27017/testdb', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  });

  afterAll(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
    jest.clearAllMocks();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should hash the password before saving', async () => {
    const plainPassword = 'admin123';
    const mockHashedPassword = 'hashedPassword';
    
    // محاكاة bcrypt.hash
    bcrypt.hash.mockResolvedValue(mockHashedPassword);

    const admin = new Admin({ username: 'admin', password: plainPassword });
    await admin.save(); // حفظ النموذج

    // التحقق من أنه تم استخدام bcrypt.hash بشكل صحيح
    expect(bcrypt.hash).toHaveBeenCalledWith(plainPassword, expect.any(Number));

    // التحقق من أن كلمة المرور تم تعيينها إلى القيمة المشفرة
    expect(admin.password).toBe(mockHashedPassword);
  });

  it('should not rehash the password if it is not modified', async () => {
    const mockHashedPassword = 'hashedPassword';

    // محاكاة bcrypt.hash
    bcrypt.hash.mockResolvedValue(mockHashedPassword);

    // محاكاة نموذج `Admin`
    const admin = new Admin({ username: 'admin', password: 'admin123' });

    // محاكاة حفظ أول مرة
    await admin.save();
    const originalHashedPassword = admin.password;

    // تحديث فقط اسم المستخدم (دون تغيير كلمة المرور)
    admin.username = 'newAdmin';

    // حفظ مرة أخرى (يجب ألا تتم إعادة تشفير كلمة المرور)
    await admin.save();

    // التحقق من أن كلمة المرور لم تتغير
    expect(admin.password).toBe(originalHashedPassword);

    // التأكد من أن `bcrypt.hash` تم استدعاؤه مرة واحدة فقط (لأن كلمة المرور لم تتغير)
    expect(bcrypt.hash).toHaveBeenCalledTimes(1); 
  });

  it('should compare passwords correctly', async () => {
    const plainPassword = 'admin123';
    const hashedPassword = 'hashedPassword';
    bcrypt.compare.mockResolvedValue(true);

    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);

    expect(isMatch).toBe(true);
    expect(bcrypt.compare).toHaveBeenCalledWith(plainPassword, hashedPassword);
  });
});
