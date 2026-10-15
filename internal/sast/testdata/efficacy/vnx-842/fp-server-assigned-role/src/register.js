async function registerUser(req, res) {
  const user = await User.create({
    email: req.body.email,
    password: await hash(req.body.password),
    role: 'customer',
    isAdmin: false,
  });
  res.status(201).json({ id: user.id, role: user.role });
}
module.exports = { registerUser };
