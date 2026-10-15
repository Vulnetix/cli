app.post("/login", (req, res, next) => {
~>  if (req.body.email.length !== 0 && req.body.password.length !== 0) {
~>    req.body.email = req.body.email.trim();
  }
~>  const user = users.find((u) => u.email === req.body.email.toLowerCase());
  next();
});
