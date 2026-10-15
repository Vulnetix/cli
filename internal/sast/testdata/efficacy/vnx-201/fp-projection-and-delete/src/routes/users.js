const User = require('../models/user');

exports.show = async (req, res) => {
  const user = await User.findById(req.params.id).select('-password -resetToken');
  res.json(user);
};

exports.me = async (req, res) => {
  const user = await User.findByPk(req.user.id, { attributes: { exclude: ['password'] } });
  res.json(user);
};

exports.raw = async (req, res) => {
  const doc = (await User.findOne({ _id: req.params.id })).toObject();
  delete doc.password;
  res.json(doc);
};

exports.changed = async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ ok: true, passwordChangedAt: user.passwordChangedAt, hasPassword: !!user.password.length });
};
