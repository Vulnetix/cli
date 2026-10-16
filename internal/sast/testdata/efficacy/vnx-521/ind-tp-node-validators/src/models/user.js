const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: {
    type: String,
    required: true,
~>    minlength: 6,
  },
  displayName: { type: String, minlength: 2 },
});

module.exports = mongoose.model("User", userSchema);
