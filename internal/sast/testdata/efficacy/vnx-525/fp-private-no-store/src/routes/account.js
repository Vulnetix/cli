router.get("/account", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ email: req.user.email });
});

router.get("/profile", requireAuth, (req, res) => {
  res.setHeader("Cache-Control", "private, max-age=60");
  res.render("profile", { user: req.user });
});

router.get("/me", requireAuth, (req, res) => {
  res.set("Cache-Control", "max-age=0, no-cache");
  res.json(req.user);
});
