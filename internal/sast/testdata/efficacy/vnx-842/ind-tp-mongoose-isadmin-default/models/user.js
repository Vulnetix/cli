const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
~>  isAdmin: { type: Boolean, default: true },
});

module.exports = mongoose.model('User', userSchema);
