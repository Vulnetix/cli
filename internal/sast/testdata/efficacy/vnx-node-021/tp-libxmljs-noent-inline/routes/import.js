const express = require('express');
const libxmljs = require('libxmljs');

const router = express.Router();

router.post('/import', express.text({ type: 'application/xml' }), (req, res) => {
~>  const doc = libxmljs.parseXml(req.body, { noent: true, noblanks: true });
  res.json({ products: doc.find('//product').length });
});

module.exports = router;
