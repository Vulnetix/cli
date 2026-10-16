exports.add = async (req, res) => {
  const p = await Product.create({ name: req.body.name, price: 10 });
  const c = Object.assign({}, req.body);
  const h = crypto.createHmac('sha256', key).update(req.body).digest('hex');
  res.json({ p, c, h });
};
