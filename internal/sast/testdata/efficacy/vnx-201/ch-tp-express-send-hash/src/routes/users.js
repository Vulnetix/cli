const router = require("express").Router();
const User = require("../models/user");

router.get("/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id).lean();
~>  res.send({ id: user._id, name: user.name, passwordHash: user.passwordHash });
});

module.exports = router;
