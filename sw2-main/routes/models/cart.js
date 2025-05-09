const mongoose = require('mongoose');

// Define the schema for the cart
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' }, // Reference to the user
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Product' }, // Reference to the product
      productName: { type: String, required: true },
      productPrice: { type: Number, required: true },
      productImage: { type: String, required: true },
      quantity: { type: Number, default: 1 } // Quantity of the product in the cart
    }
  ]
}, { timestamps: true }); // `timestamps` will automatically add createdAt and updatedAt fields

// Create and export the Cart model
const Cart = mongoose.model('Cart', cartSchema);
module.exports = Cart;
