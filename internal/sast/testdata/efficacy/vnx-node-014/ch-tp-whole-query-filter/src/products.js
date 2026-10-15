exports.list = async (req, res) => {
~>  const items = await req.app.locals.db.collection('products').find(req.query).toArray();
  res.json(items);
};
