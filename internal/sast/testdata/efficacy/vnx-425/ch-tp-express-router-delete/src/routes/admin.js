const express = require('express');
const router = express.Router();
const User = require('../models/user');

~>router.delete('/admin/users/:id', async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});

~>router.post("/admin/settings", updateSettings);

module.exports = router;
