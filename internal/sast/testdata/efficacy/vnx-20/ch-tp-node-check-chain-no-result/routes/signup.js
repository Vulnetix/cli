const express = require("express");
const { check, query } = require("express-validator");
const router = express.Router();

router.post(
  "/signup",
~>  check("email").isEmail().normalizeEmail(),
~>  check("password").isLength({ min: 12 }),
  async (req, res) => {
    await users.create(req.body);
    res.redirect("/welcome");
  }
);

~>router.get("/search", query("q").trim().isLength({ max: 64 }), (req, res) => {
  res.json(search(req.query.q));
});

module.exports = router;
