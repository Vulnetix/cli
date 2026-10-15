router.put("/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
~>  user.set(req.body);
  await user.save();
  res.json(user);
});
