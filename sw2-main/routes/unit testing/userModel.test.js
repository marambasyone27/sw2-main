const bcrypt = require('bcrypt');
const User = require('../models/users');

jest.mock('bcrypt');

describe('User Model - Unit Tests', () => {
  describe('Validation', () => {
    it('should throw validation error if required fields are missing', async () => {
      const user = new User({}); 

      let err;
      try {
        await user.validate(); 
      } catch (error) {
        err = error;
      }

      expect(err).toBeDefined();
      expect(err.errors.name).toBeDefined();
      expect(err.errors.email).toBeDefined();
      expect(err.errors.phone).toBeDefined();
      expect(err.errors.password).toBeDefined();
      expect(err.errors.gender).toBeDefined();
    });

    it('should pass validation when all required fields are provided', async () => {
      const user = new User({
        name: 'John Doe',
        email: 'john@example.com',
        phone: '1234567890',
        password: 'securePass',
        gender: 'male'
      });

      let err;
      try {
        await user.validate(); 
      } catch (error) {
        err = error;
      }

      expect(err).toBeUndefined();
    });
  });

  describe('comparePassword method', () => {
    it('should return true if passwords match', async () => {
      const user = new User({ password: 'hashedPassword' });
      bcrypt.compare.mockResolvedValue(true);

      const result = await user.comparePassword('plainPassword');
      expect(bcrypt.compare).toHaveBeenCalledWith('plainPassword', 'hashedPassword');
      expect(result).toBe(true);
    });

    it('should return false if passwords do not match', async () => {
      const user = new User({ password: 'hashedPassword' });
      bcrypt.compare.mockResolvedValue(false);

      const result = await user.comparePassword('wrongPassword');
      expect(result).toBe(false);
    });
  });
});
