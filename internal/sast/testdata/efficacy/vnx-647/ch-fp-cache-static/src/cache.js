app.use((req, res, next) => {
  if (req.path.startsWith("/static/")) {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  }
  next();
});
