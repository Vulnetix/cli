router.post("/prefs", (req, res) => {
  const body = req.body;
~>  Object.assign(req.session, body);
  res.sendStatus(204);
});

router.post("/me", (req, res) => {
~>  Object.assign(req.user, req.body);
  res.json(req.user);
});
