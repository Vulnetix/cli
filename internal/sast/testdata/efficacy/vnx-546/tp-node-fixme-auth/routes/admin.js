router.delete('/users/:id', async (req, res) => {
~>  // FIXME: no authorization check here, any logged-in user can delete
  await User.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
