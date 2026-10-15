const User = require('./user');

exports.find = async (req, res) => {
  const users = await User.find({ name: String(req.query.name) }).exec();
  const m = /^(\d+)-(\w+)$/.exec(req.params.slug);
  res.json({ users, m });
};
