app.get('/u/:id', async (req, res) => {
  const u = await User.findById(req.params.id);
  const rows = await Order.findAll({ where: { owner: req.query.owner } });
  res.json({ u, rows });
});
