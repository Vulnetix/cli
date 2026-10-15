const _ = require("lodash");
router.post("/users", async (req, res) => {
  const user = await User.create(_.pick(req.body, ["name", "email"]));
  res.json(user);
});
