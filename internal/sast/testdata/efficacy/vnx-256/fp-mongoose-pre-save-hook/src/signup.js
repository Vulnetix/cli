router.post("/signup", async (req, res) => {
  const user = new User({ email: req.body.email, password: req.body.password });
  await user.save();
});
