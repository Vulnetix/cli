const express = require('express');
const router = express.Router();

router.get('/orders/:id', (req, res) => {
~>  if (!/[0-9]{1,10}$/.test(req.params.id)) {
    return res.status(400).end();
  }
  res.json({ id: req.params.id });
});
module.exports = router;
