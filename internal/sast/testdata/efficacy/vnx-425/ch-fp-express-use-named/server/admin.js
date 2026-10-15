const express = require("express");
const { authorize } = require("./middleware/authorize");

const router = express.Router();
router.use(authorize("admin"));

router.get("/admin/users", (req, res) => {
  res.json(listUsers());
});

router.delete("/admin/users/:id", (req, res) => {
  deleteUser(req.params.id);
  res.sendStatus(204);
});

module.exports = router;
