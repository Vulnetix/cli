const router = require("express").Router();
const passport = require("passport");

router.get("/auth/google", passport.authenticate("google", { scope: ["profile"], state: true }));

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/")
);

module.exports = router;
