const express = require('express');
const router = express.Router();

router.get('/:id', async (req, res) => {
  res.json({ id: req.params.id });
});

module.exports = router;
