const express = require("express");
const router = express.Router();

router.post("/login", async (req, res) => {
  const { returnTo } = req.query;
  await req.session.regenerate();
~>  res.redirect(returnTo);
});

module.exports = router;
