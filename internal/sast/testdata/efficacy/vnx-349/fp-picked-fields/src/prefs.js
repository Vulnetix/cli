router.post("/prefs", (req, res) => {
  Object.assign(req.session, { theme: String(req.body.theme) });
  const ctx = { ...claims, locale: req.query.locale };
  res.sendStatus(204);
});
