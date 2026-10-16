router.put('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
~>  Object.assign(user, req.body);
  await user.save();
~>  await User.findByIdAndUpdate(req.params.id, req.body);
  res.sendStatus(204);
});
