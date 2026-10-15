const router = require("express").Router();

router.get("/admin", (req, res) => {
~>  const role = req.cookies.role;
  if (role === "admin") {
    return res.render("admin");
  }
  res.status(403).end();
});
module.exports = router;
