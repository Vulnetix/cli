const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: String,
  password: { type: String, select: false },
});

const User = mongoose.model('User', UserSchema);

async function show(req, res) {
  const user = await User.findById(req.params.id);
  res.json(user);
}

module.exports = { User, show };
