const mongoose = require('mongoose');
const Cart = require('../models/cart');

async function addToCart({ userId, productId, productName, productPrice, productImage }) {
  if (!userId || !productId || !productName || !productPrice || !productImage) {
    throw new Error('All fields are required.');
  }

  let cart = await Cart.findOne({ userId: new mongoose.Types.ObjectId(userId) });

  if (!cart) {
    cart = new Cart({
      userId: new mongoose.Types.ObjectId(userId),
      items: [{
        productId: new mongoose.Types.ObjectId(productId),
        productName,
        productPrice,
        productImage,
        quantity: 1
      }]
    });
  } else {
    const existingItem = cart.items.find(item => item.productId.toString() === productId);
    if (existingItem) {
      existingItem.quantity += 1;
    } else {
      cart.items.push({
        productId: new mongoose.Types.ObjectId(productId),
        productName,
        productPrice,
        productImage,
        quantity: 1
      });
    }
  }

  await cart.save();
  return cart;
}

async function getCart(userId) {
  const cart = await Cart.findOne({ userId: new mongoose.Types.ObjectId(userId) });
  return cart || { items: [] };
}

async function removeFromCart(userId, productId) {
  const cart = await Cart.findOne({ userId: new mongoose.Types.ObjectId(userId) });
  if (!cart) throw new Error('No cart found for this user');

  cart.items = cart.items.filter(item => item.productId.toString() !== productId);
  await cart.save();
  return cart;
}

module.exports = {
  addToCart,
  getCart,
  removeFromCart
};
