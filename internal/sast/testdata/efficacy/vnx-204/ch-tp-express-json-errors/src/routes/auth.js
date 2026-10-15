const router = require("express").Router();
const bcrypt = require("bcrypt");

router.post("/login", async (req, res) => {
  const user = await req.app.locals.db.users.findOne({ email: req.body.email });
  if (!user) {
~>    return res.status(401).json({ error: "User not found" });
  }
  const ok = await bcrypt.compare(req.body.password, user.hash);
  if (!ok) {
    return res.status(401).json({ error: "Incorrect password" });
  }
  req.session.uid = user.id;
  res.json({ ok: true });
});

module.exports = router;
