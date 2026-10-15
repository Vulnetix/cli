const sanitize = require('mongo-sanitize');

exports.lookup = async (req, res) => {
  const email = sanitize(req.body.email);
  const user = await User.findOne({ email });
  res.json(user);
};
