router.post('/account/change-password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);
  const ok = await bcrypt.compare(currentPassword, user.password);
  if (!ok) {
    return res.status(401).send('wrong password');
  }
  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  res.sendStatus(204);
});
