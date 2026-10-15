const argon2 = require('argon2');
const User = require('../models/user');

exports.changePassword = async (req, res, next) => {
  try {
    const hashed = await argon2.hash(req.body.password);
~>    await User.findByIdAndUpdate(req.user._id, { password: hashed });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};
