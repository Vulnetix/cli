const router = require("express").Router();

router.get("/account/settings", ensureLoggedIn, (req, res) => {
~>  res.set({ "Cache-Control": "public, max-age=300", "Content-Type": "application/json" });
  res.send(JSON.stringify(req.user.settings));
});

module.exports = router;
