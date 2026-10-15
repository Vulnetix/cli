app.use((req, res, next) => {
~>  if (req.originalUrl.indexOf("/api/admin") === 0 && req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  next();
});
