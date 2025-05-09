const mongoose = require('mongoose');
const { Schema } = mongoose;
const Product = require('../models/products'); 

describe('Product Model - Unit Tests', () => {
  it('should throw validation error if required fields are missing', async () => {
    const product = new Product({ name: '', price: null }); 
    let err;
    try {
      await product.validate();
    } catch (error) {
      err = error;
    }

    expect(err).toBeDefined();
    expect(err.errors.name).toBeDefined();
    expect(err.errors.price).toBeDefined();
  });

  it('should pass validation with valid fields', async () => {
    const product = new Product({
      name: 'Test Product',
      price: 99.99,
      description: 'Sample desc',
      image: 'sample.png'
    });

    let err;
    try {
      await product.validate(); 
    } catch (error) {
      err = error;
    }

    expect(err).toBeUndefined();
  });
});
