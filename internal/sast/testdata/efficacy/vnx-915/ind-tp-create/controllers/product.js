exports.add = async (req, res) => {
~>  const p = await Product.create(req.body);
  res.json(p);
};
