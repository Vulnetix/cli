const express = require('express');
const path = require('path');
const { canAccess } = require('../auth/policy');

const router = express.Router();
const DOC_ROOT = path.join(__dirname, '..', '..', 'documents');

router.get('/docs/:doc', async (req, res, next) => {
  const docName = req.params.doc;

~>  if (!canAccess(req.user, docName)) {
    return res.status(403).send('forbidden');
  }

  const normalized = path.normalize(docName);
  res.sendFile(path.join(DOC_ROOT, normalized));
});

module.exports = router;
