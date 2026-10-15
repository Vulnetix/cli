const express = require("express");
const router = express.Router();
const settings = require("../controllers/settings");

~>router.route("/admin/settings").get(settings.show).post(settings.update);

module.exports = router;
