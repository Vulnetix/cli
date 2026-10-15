router.post('/profile', async (req, res) => {
  const user = await User.findById(req.user.id);
  user.state = req.body.state;
  profile.status = req.body.status;
  user.city = req.body.city;
  await user.save();
  res.status(200).json(user);
});

function Widget() {
  this.setState({ status: props.status });
}
