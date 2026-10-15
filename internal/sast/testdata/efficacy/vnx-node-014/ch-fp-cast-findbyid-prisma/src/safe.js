exports.get = async (req, res) => {
  const a = await User.findOne({ username: String(req.body.username) });
  const b = await User.findById(req.params.id);
  const c = await prisma.user.findUnique({ where: { email: req.body.email } });
  const d = items.find((x) => x.id === req.body.id);
  res.json({ a, b, c, d });
};
