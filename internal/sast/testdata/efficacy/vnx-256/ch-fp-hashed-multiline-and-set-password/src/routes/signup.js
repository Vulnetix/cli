const bcrypt = require("bcrypt");

router.post("/signup", async (req, res) => {
  await User.create({
    email: req.body.email,
    password: await bcrypt.hash(req.body.password, 12),
  });
  const session = await auth.login({
    username: req.body.username,
    password: req.body.password,
  });
  res.json(session);
});
