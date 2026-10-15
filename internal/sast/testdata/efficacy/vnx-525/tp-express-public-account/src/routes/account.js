const router = require("express").Router();

router.get("/account", requireAuth, (req, res) => {
~>  res.set("Cache-Control", "public, max-age=600");
  res.json({ email: req.user.email, balance: req.user.balance });
});

router.get("/profile", async (req, res) => {
  const profile = await Profile.findById(req.session.userId);
~>  res.setHeader('Cache-Control', 'max-age=86400');
  res.render("profile", { profile });
});

router.get("/api/token", (req, res) => {
~>  res.header("Cache-Control", "public");
  res.json({ token: issueToken(req.user) });
});

module.exports = router;
