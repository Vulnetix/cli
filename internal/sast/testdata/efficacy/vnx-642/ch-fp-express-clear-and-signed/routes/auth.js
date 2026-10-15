const express = require("express");
const router = express.Router();

router.post("/login", async (req, res) => {
  const user = await users.check(req.body.email, req.body.password);
  res.cookie("role", user.role, {
    httpOnly: true,
    sameSite: "strict",
    signed: true,
  });
  res.redirect("/");
});

router.post("/logout", (req, res) => {
  res.clearCookie("isAdmin");
  res.clearCookie("role");
  res.redirect("/login");
});

router.get("/admin", (req, res, next) => {
  if (req.signedCookies.role !== "admin") return res.sendStatus(403);
  next();
});

module.exports = router;
