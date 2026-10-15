router.post('/admin/users/:id/change-password', requireRole('admin'), async (req, res) => {
  if (!req.user.isAdmin) return res.sendStatus(403);
  const user = await User.findById(req.params.id);
  user.password = await bcrypt.hash(req.body.newPassword, 12);
  await user.save();
  res.sendStatus(204);
});
