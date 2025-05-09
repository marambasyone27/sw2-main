
const express = require("express");
const multer = require("multer");
const path = require("path");
const Product = require("./models/products");
const router = express.Router();

// Setup multer for image uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const filename = Date.now() + ext;
    cb(null, filename);
  }
});

const upload = multer({ storage });

// Route to add a new product
router.post("/add", upload.single("image"), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : ""; // Ensure image is uploaded

    const newProduct = new Product({
      name,
      description,
      price,
      image,
     
    });

    await newProduct.save();
    res.status(201).json({ msg: "Product added successfully", product: newProduct });
  } catch (err) {
    console.log(`Error saving product: ${err}`);
    res.status(500).json({ msg: "Server error" });
  }
});

// Route to get all products (optional, you can also get them filtered by category)
router.get("/", async (req, res) => {
  try {
    const products = await Product.find(); // Fetch all products
    res.json(products);
  } catch (err) {
    console.log(`Error fetching products: ${err}`);
    res.status(500).json({ msg: "Server error" });
  }
});

// Route to update product by ID (Edit functionality)
router.put("/:id", upload.single("image"), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null; // Check if a new image was uploaded

    // Prepare update fields
    const updateFields = { name, description, price, category };
    if (image) {
      updateFields.image = image; // Update image if a new one was uploaded
    }

    // Find and update the product by ID
    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ msg: "Product not found" }); // السطر 79-80
    }

    res.json({ msg: "Product updated successfully", product: updatedProduct });
  } catch (err) {
    console.log(`Error updating product: ${err}`);
    res.status(500).json({ msg: "Server error" });
  }
});

// Route to delete a product by ID
router.delete("/:id", async (req, res) => {
  try {
    const result = await Product.findByIdAndDelete(req.params.id);
    if (!result) {
      return res.status(404).json({ msg: "Product not found" }); // السطر 93-94
    }
    res.json({ msg: "Product deleted successfully" });
  } catch (err) {
    console.log(`Error deleting product: ${err}`);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
