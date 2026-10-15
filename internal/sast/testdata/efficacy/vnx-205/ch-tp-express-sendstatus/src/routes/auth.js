const router = require("express").Router();
const bcrypt = require("bcryptjs");

router.post("/login", async (req, res) => {
  const user = await req.app.locals.db.users.findOne({ email: req.body.email });
~>  if (!user) return res.sendStatus(401);
  const ok = await bcrypt.compare(req.body.password, user.hash);
  if (!ok) return res.sendStatus(401);
  res.json({ ok: true });
});

module.exports = router;
