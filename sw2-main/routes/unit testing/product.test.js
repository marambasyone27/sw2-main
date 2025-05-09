const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const path = require('path');
const fs = require('fs');
const app = require('../app');
const Product = require('../models/products');

jest.setTimeout(180000);

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
  await Product.deleteMany();
});

describe('Product Routes', () => {
  it('should create a new product with image', async () => {
    const imagePath = path.join(__dirname, 'testImage.jpeg');
    if (!fs.existsSync(imagePath)) {
      console.log("testImage.jpeg not found in test folder");
    }

    const res = await request(app)
      .post('/api/products/add')
      .field('name', 'Test Product')
      .field('description', 'Test description')
      .field('price', 150)
      .field('category', 'Electronics')
      .attach('image', imagePath);

    expect(res.status).toBe(201);
    expect(res.body.product).toHaveProperty('name', 'Test Product');
  });

  it('should return 500 if saving product fails', async () => {
    jest.spyOn(Product.prototype, 'save').mockImplementationOnce(() => {
      throw new Error('Save failed');
    });

    const imagePath = path.join(__dirname, 'testImage.jpeg');
    const res = await request(app)
      .post('/api/products/add')
      .field('name', 'Fail Product')
      .field('description', 'desc')
      .field('price', 100)
      .field('category', 'Fail')
      .attach('image', imagePath);

    expect(res.status).toBe(500);
    expect(res.body.msg).toBe('Server error');
  });

  it('should fetch all products', async () => {
    await Product.create({
      name: 'Test Product 2',
      description: 'desc',
      price: 100,
      category: 'Misc',
      image: '/uploads/test.jpg'
    });

    const res = await request(app).get('/api/products');

    expect(res.status).toBe(200);
    expect(res.body.length).toBe(1);
  });

  it('should return 500 when fetching products fails', async () => {
    jest.spyOn(Product, 'find').mockImplementationOnce(() => {
      throw new Error("DB error");
    });

    const res = await request(app).get('/api/products');

    expect(res.status).toBe(500);
    expect(res.body.msg).toBe('Server error');
  });

  it('should update a product', async () => {
    const product = await Product.create({
      name: 'Old Name',
      description: 'Old desc',
      price: 50,
      category: 'OldBook',
      image: '/uploads/test.jpg'
    });

    const res = await request(app)
      .put(`/api/products/${product._id}`)
      .send({
        name: 'New Name',
        description: 'Updated',
        price: 200,
        category: 'UpdatedBook'
      });

    expect(res.status).toBe(200);
    expect(res.body.product.name).toBe('New Name');
  });

  it('should return 404 when updating non-existent product', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await request(app)
      .put(`/api/products/${fakeId}`)
      .send({
        name: 'New',
        description: 'desc',
        price: 100,
        category: 'Book'
      });

    expect(res.status).toBe(404);
    expect(res.body.msg).toBe('Product not found');
  });

  it('should return 500 if updating product throws error', async () => {
    jest.spyOn(Product, 'findByIdAndUpdate').mockImplementationOnce(() => {
      throw new Error('Update failed');
    });

    const product = await Product.create({
      name: 'Error Product',
      description: 'desc',
      price: 10,
      category: 'Err',
      image: '/uploads/test.jpg'
    });

    const res = await request(app)
      .put(`/api/products/${product._id}`)
      .send({
        name: 'Err',
        description: 'Err',
        price: 10,
        category: 'Err'
      });

    expect(res.status).toBe(500);
    expect(res.body.msg).toBe('Server error');
  });

  it('should return 404 when deleting non-existent product', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await request(app).delete(`/api/products/${fakeId}`);

    expect(res.status).toBe(404);
    expect(res.body.msg).toBe('Product not found');
  });

  it('should delete a product', async () => {
    const product = await Product.create({
      name: 'To Delete',
      description: 'desc',
      price: 30,
      category: 'Cat',
      image: '/uploads/test.jpg'
    });

    const res = await request(app).delete(`/api/products/${product._id}`);

    expect(res.status).toBe(200);
    expect(res.body.msg).toBe('Product deleted successfully');
  });
   
  it('should return 500 if deleting product throws error', async () => {
    jest.spyOn(Product, 'findByIdAndDelete').mockImplementationOnce(() => {
      throw new Error('Delete failed');
    });

    const product = await Product.create({
      name: 'Err Delete',
      description: 'desc',
      price: 20,
      category: 'ErrCat',
      image: '/uploads/test.jpg'
    });

    const res = await request(app).delete(`/api/products/${product._id}`);

    expect(res.status).toBe(500);
    expect(res.body.msg).toBe('Server error');
  });
});
