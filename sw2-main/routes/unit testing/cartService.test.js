const mongoose = require('mongoose');
const Cart = require('../models/cart');
const { addToCart, getCart, removeFromCart } = require('../services/cartService');

jest.mock('../models/cart');
//jest.setTimeout(180000);
describe('Cart Service', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  const sampleUserId = new mongoose.Types.ObjectId();

  const sampleCart = {
    userId: sampleUserId,
    items: [],
    save: jest.fn(),
  };

  test('should increase quantity if product already exists in cart', async () => {
    const existingItem = {
      productId: new mongoose.Types.ObjectId(),
      quantity: 1,
    };
    const fakeCart = {
      userId: sampleCart.userId,
      items: [existingItem],
      save: jest.fn(),
    };

    Cart.findOne.mockResolvedValue(fakeCart);

    await addToCart({
      userId: fakeCart.userId,
      productId: existingItem.productId.toString(),
      productName: 'Test Product',
      productPrice: 100,
      productImage: 'img.jpg',
    });

    expect(existingItem.quantity).toBe(2);
    expect(fakeCart.save).toHaveBeenCalled();
  });

  test('should add new product to existing cart if not found', async () => {
    const fakeCart = {
      userId: sampleCart.userId,
      items: [],
      save: jest.fn(),
    };

    Cart.findOne.mockResolvedValue(fakeCart);

    await addToCart({
      userId: fakeCart.userId,
      productId: new mongoose.Types.ObjectId(),
      productName: 'New Product',
      productPrice: 150,
      productImage: 'image.jpg',
    });

    expect(fakeCart.items.length).toBe(1);
    expect(fakeCart.save).toHaveBeenCalled();
  });

  test('should create a new cart if user has no existing cart', async () => {
    Cart.findOne.mockResolvedValue(null);
    const mockSave = jest.fn();

    Cart.mockImplementation(() => ({
      save: mockSave,
    }));

    await addToCart({
      userId: sampleUserId,
      productId: new mongoose.Types.ObjectId(),
      productName: 'Fresh Product',
      productPrice: 200,
      productImage: 'fresh.jpg',
    });

    expect(mockSave).toHaveBeenCalled();
  });

  test('should throw error if required fields are missing', async () => {
    await expect(addToCart({})).rejects.toThrow('All fields are required.');
  });

  test('should remove product from cart successfully', async () => {
    const productIdToRemove = new mongoose.Types.ObjectId().toString();

    const fakeCart = {
      userId: sampleCart.userId,
      items: [{ productId: productIdToRemove }],
      save: jest.fn(),
    };

    Cart.findOne.mockResolvedValue(fakeCart);

    const updatedCart = await removeFromCart(fakeCart.userId, productIdToRemove);

    expect(updatedCart.items.length).toBe(0);
    expect(fakeCart.save).toHaveBeenCalled();
  });

  test('should throw error if no cart found when removing item', async () => {
    Cart.findOne.mockResolvedValue(null);

    await expect(
      removeFromCart(sampleUserId, new mongoose.Types.ObjectId().toString())
    ).rejects.toThrow('No cart found for this user');
  });

  test('should return empty items array if user has no cart', async () => {
    Cart.findOne.mockResolvedValue(null);

    const result = await getCart(sampleUserId);

    expect(result).toEqual({ items: [] });
  });

  test('should return cart if found', async () => {
    const fakeCart = {
      userId: sampleUserId,
      items: [{ productId: new mongoose.Types.ObjectId() }],
    };

    Cart.findOne.mockResolvedValue(fakeCart);

    const result = await getCart(sampleUserId);

    expect(result).toEqual(fakeCart);
  });
});
