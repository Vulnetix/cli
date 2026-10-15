const ALLOWED_LANGS = ["en", "de", "fr"];

app.get("/page", (req, res) => {
  const lang = ALLOWED_LANGS.includes(req.query.lang) ? req.query.lang : "en";
  res.setHeader("Content-Language", lang);
  res.render("page", { lang });
});
