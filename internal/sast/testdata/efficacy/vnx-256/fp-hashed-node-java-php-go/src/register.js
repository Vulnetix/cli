router.post("/signup", async (req, res) => {
  const user = new User({ email: req.body.email, password: await bcrypt.hash(req.body.password, 10) });
  const hashed = await argon2.hash(req.body.password);
  await Account.create({ username: req.body.username, password: hashed });
});
