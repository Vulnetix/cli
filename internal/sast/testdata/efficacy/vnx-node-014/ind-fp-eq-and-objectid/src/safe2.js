const { ObjectId } = require('mongodb');

app.get('/doc/:id', async (req, res) => {
  const d = await db.collection('docs').findOne({ _id: new ObjectId(req.params.id) });
  const e = await db.collection('docs').findOne({ email: { $eq: req.query.email } });
  res.json({ d, e });
});
