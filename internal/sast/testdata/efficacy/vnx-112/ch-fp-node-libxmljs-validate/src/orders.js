const fs = require('fs');
const express = require('express');
const libxmljs = require('libxmljs2');

const xsd = libxmljs.parseXml(fs.readFileSync('schemas/order.xsd', 'utf8'));
const app = express();

app.post('/orders', (req, res) => {
  const doc = libxmljs.parseXml(req.body);
  if (!doc.validate(xsd)) {
    return res.status(422).json({ errors: doc.validationErrors.map(String) });
  }
  res.json({ ok: true });
});
