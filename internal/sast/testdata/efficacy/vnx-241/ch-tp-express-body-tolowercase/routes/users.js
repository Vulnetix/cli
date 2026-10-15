const router = require("express").Router();

router.post("/users/lookup", async (req, res) => {
~>  const email = req.body.email.toLowerCase();
  const user = await User.findOne({ email });
  res.json({ exists: Boolean(user) });
});

module.exports = router;
