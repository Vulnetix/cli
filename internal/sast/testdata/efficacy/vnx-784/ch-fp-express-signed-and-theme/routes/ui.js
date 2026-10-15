router.get("/", (req, res) => {
  if (req.signedCookies.role === "admin") {
    return res.render("admin");
  }
  if (req.cookies.theme === "dark") {
    res.locals.dark = true;
  }
  res.cookie("admin", "false", { httpOnly: true, signed: true });
  res.render("index");
});
