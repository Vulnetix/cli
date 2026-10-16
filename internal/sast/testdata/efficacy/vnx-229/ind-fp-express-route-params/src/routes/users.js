const router = require("express").Router();

router.get("/users/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = await User.findByPk(id);
  res.json(user);
});

module.exports = router;
