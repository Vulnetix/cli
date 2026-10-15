async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  if (!ok) {
    user.loginAttempts = (user.loginAttempts || 0) + 1;
    if (user.loginAttempts > 5) {
~>      user.active = false;
    }
    await user.save();
    return res.status(401).send('invalid');
  }
  user.loginAttempts = 0;
  await user.save();
  res.json({ token: sign(user) });
}
