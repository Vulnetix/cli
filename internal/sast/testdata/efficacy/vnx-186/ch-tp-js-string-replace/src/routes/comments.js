const express = require("express");
const router = express.Router();

router.post("/comments", async (req, res) => {
  const body = req.body.text;
~>  const cleaned = body.replace("<script>", "");
  await req.app.locals.db.insertComment(cleaned);
  res.redirect("/comments");
});

module.exports = router;
