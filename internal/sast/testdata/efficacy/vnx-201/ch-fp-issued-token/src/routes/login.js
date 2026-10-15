const router = require("express").Router();
const jwt = require("jsonwebtoken");

router.post("/login", async (req, res) => {
  const user = await req.app.locals.auth.verify(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ token, expiresIn: 3600 });
});

module.exports = router;
