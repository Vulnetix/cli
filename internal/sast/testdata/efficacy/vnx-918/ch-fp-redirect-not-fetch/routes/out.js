router.get("/out", (req, res) => {
  const dest = req.query.to;
  audit.fetchLog(dest);
  res.redirect(302, dest);
});
