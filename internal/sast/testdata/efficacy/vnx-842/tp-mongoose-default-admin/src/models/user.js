const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  role: {
    type: String,
    enum: ['admin', 'editor', 'viewer'],
~>    default: 'admin',
  },
~>  isAdmin: { type: Boolean, default: true },
});

module.exports = mongoose.model('User', userSchema);
