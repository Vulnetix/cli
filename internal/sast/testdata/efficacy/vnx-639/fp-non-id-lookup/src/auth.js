async function login(req, res) {
  const user = await User.findOne({ where: { email: req.body.email } });
  // Order.findById(req.params.id) is unsafe without an owner check
  const msg = "Order.findById(req.params.id)";
  res.json({ ok: !!user, msg });
}
module.exports = { login };
