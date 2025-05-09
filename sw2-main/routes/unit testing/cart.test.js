const request = require('supertest');
const express = require('express');
const cartRouter = require('../cartRoute');
const cartService = require('../services/cartService');

jest.mock('../services/cartService');
jest.setTimeout(150000);

const app = express();
app.use(express.json());
app.use('/cart', cartRouter);

describe('Cart Routes', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should add product to cart', async () => {
    const fakeCart = { userId: '123', products: ['456'] };
    cartService.addToCart.mockResolvedValue(fakeCart);

    const res = await request(app)
      .post('/cart/add')
      .send({ userId: '123', productId: '456' });

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Product added to cart successfully');
    expect(res.body.cart).toEqual(fakeCart);
    expect(cartService.addToCart).toHaveBeenCalledWith({ userId: '123', productId: '456' });
  });

  it('should get user cart', async () => {
    const fakeCart = { userId: '123', products: ['456'] };
    cartService.getCart.mockResolvedValue(fakeCart);

    const res = await request(app).get('/cart/123');

    expect(res.status).toBe(200);
    expect(res.body.cart).toEqual(fakeCart);
    expect(cartService.getCart).toHaveBeenCalledWith('123');
  });

  it('should remove product from cart', async () => {
    const updatedCart = { userId: '123', products: [] };
    cartService.removeFromCart.mockResolvedValue(updatedCart);

    const res = await request(app)
      .delete('/cart/remove')
      .send({ userId: '123', productId: '456' });

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Product removed from cart');
    expect(res.body.cart).toEqual(updatedCart);
    expect(cartService.removeFromCart).toHaveBeenCalledWith('123', '456');
  });

  it('should handle errors in addToCart', async () => {
    cartService.addToCart.mockRejectedValue(new Error('Add failed'));

    const res = await request(app)
      .post('/cart/add')
      .send({ userId: '123', productId: '456' });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Add failed');
  });

  it('should handle errors in getCart', async () => {
    cartService.getCart.mockRejectedValue(new Error('Get failed'));

    const res = await request(app).get('/cart/123');

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Get failed');
  });

  it('should handle errors in removeFromCart', async () => {
    cartService.removeFromCart.mockRejectedValue(new Error('Remove failed'));

    const res = await request(app)
      .delete('/cart/remove')
      .send({ userId: '123', productId: '456' });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Remove failed');
  });
});
