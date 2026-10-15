const router = require("express").Router();
const bcrypt = require("bcrypt");

const BAD = "Invalid email or password";

router.post("/login", async (req, res) => {
  const user = await req.app.locals.db.users.findOne({ email: req.body.email });
  if (!user) {
    return res.status(401).json({ error: BAD });
  }
  if (!(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: BAD });
  }
  res.json({ ok: true });
});

module.exports = router;
