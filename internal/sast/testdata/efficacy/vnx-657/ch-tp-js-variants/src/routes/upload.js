const express = require('express');
const router = express.Router();

~>// XXX: no auth check here yet
router.post('/upload', (req, res) => {
~>  /* HACK: skip permission check for admins */
  save(req.files);
~>  res.send(req.body.name); // TODO(bob): escape user input before echoing
});

module.exports = router;
