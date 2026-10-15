const router = require("express").Router();
const User = require("../models/user");

router.get("/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id).lean();
  res.json({ id: user._id, email: user.email, name: user.name });
});

module.exports = router;
