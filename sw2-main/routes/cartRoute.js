const express = require('express');
const router = express.Router();
const { addToCart, getCart, removeFromCart } = require('./services/cartService'); // ✅ تعديل المسار

router.post('/add', async (req, res) => {
  try {
    const cart = await addToCart(req.body);
    res.status(200).json({ message: 'Product added to cart successfully', cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get('/:userId', async (req, res) => {
  try {
    const cart = await getCart(req.params.userId);
    res.status(200).json({ cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.delete('/remove', async (req, res) => {
  try {
    const cart = await removeFromCart(req.body.userId, req.body.productId);
    res.status(200).json({ message: 'Product removed from cart', cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
