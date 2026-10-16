const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");

const memberSchema = new mongoose.Schema({
  email: String,
  password: String,
});

memberSchema.pre("save", async function hashPassword(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

module.exports = mongoose.model("Member", memberSchema);
