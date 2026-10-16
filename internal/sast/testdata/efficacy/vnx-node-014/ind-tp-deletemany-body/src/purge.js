app.post('/purge', async (req, res) => {
~>  await User.deleteMany(req.body);
  res.sendStatus(204);
});
