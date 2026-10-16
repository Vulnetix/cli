const _ = require("lodash");
const router = require("express").Router();

router.post("/profile/preview", (req, res) => {
  const input = req.body;
~>  const view = _.merge(req.user, input);
  res.json(view);
});

module.exports = router;
