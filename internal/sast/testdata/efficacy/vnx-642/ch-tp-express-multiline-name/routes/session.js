const express = require("express");
const router = express.Router();

router.post("/login", async (req, res) => {
  const user = await users.check(req.body.email, req.body.password);
~>  res.cookie(
    "userRole",
    user.role,
    { httpOnly: true, maxAge: 3600000 }
  );
  res.redirect("/home");
});

module.exports = router;
