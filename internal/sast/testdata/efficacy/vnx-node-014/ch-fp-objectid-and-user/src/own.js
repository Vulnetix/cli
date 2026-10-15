const { ObjectId } = require('mongodb');

exports.mine = async (req, res) => {
  const doc = await notes.findOne({ _id: new ObjectId(req.params.id), owner: req.user.id });
  const n = await notes.countDocuments({ status: 'active' });
  res.json({ doc, n });
};
