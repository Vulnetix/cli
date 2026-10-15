const router = require("express").Router();
const User = require("../models/user");

router.get("/me", async (req, res) => {
  const doc = await User.findById(req.session.uid).lean();
  const { password, passwordHash, ...safe } = doc;
  res.json(safe);
});

module.exports = router;
