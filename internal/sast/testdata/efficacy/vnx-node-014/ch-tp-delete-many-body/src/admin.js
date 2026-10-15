const { getDb } = require('./db');

exports.purge = async (req, res) => {
  const db = await getDb();
~>  const result = await db.collection('sessions').deleteMany(req.body);
  res.json({ deleted: result.deletedCount });
};
