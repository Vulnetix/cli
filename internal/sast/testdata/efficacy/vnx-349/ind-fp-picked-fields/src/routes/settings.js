const router = require("express").Router();

router.post("/settings", (req, res) => {
  const prefs = { theme: req.body.theme, locale: req.body.locale };
  const view = { ...req.user, ...prefs };
  res.render("settings", { user: req.user, prefs });
  res.json(view);
});

module.exports = router;
