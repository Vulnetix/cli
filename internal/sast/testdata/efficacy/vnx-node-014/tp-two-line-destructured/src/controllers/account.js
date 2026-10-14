const { MongoClient } = require('mongodb');

async function reset(req, res) {
  const { email } = req.body;
~>  const account = await res.locals.db.collection('accounts').findOne({ email });
  res.json({ found: Boolean(account) });
}

async function rename(req, res) {
  const filter = { owner: req.query.owner };
~>  await res.locals.db.collection('projects').updateOne(filter, { $set: { name: 'x' } });
  res.sendStatus(204);
}

module.exports = { reset, rename };
