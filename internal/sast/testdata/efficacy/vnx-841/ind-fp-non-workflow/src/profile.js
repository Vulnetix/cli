app.post('/profile', async (req, res) => {
  const profile = await Profile.findById(req.user.id);
  profile.status = req.body.status;
  address.state = req.body.state;
  res.status(200).json({ ok: true });
});
