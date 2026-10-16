const express = require("express");
const router = express.Router();

router.post("/preview", (req, res) => {
~>  res.render("preview", { title: "Preview", ...req.body });
});

module.exports = router;
