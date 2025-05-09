const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,  // Adding required validation for name
  },
  email: {
    type: String,
    required: true,  // Adding required validation for email
    unique: true,
    lowercase: true,  // Ensuring email is stored in lowercase
  },
  phone: {
    type: String,
    required: true,  // Adding required validation for phone number
  },
  password: {
    type: String,
    required: true,  // Ensuring password is required
  },
  gender: { 
    type: String, 
    required: true 
  },
});


// Method to compare password during login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
