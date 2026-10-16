const bcrypt = require('bcryptjs');
const User = require('../models/User');

const MAX_FAILED = 5;

async function login(email, password) {
  const user = await User.findOne({ email });
  if (!user || !user.active) throw new Error('Invalid credentials');
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= MAX_FAILED) {
~>      user.active = false;
    }
    await user.save();
    throw new Error('Invalid credentials');
  }
  user.loginAttempts = 0;
  await user.save();
  return user;
}

module.exports = { login };
