exports.byOwner = async (req, res) => {
~>  const docs = await db.collection('notes').find({
    $where: "this.owner == '" + req.query.owner + "'",
  }).toArray();
  res.json(docs);
};
