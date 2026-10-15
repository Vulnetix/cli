const express = require('express');
const xml2js = require('xml2js');
const router = express.Router();

router.post('/feed', express.text({ type: 'application/xml' }), (req, res) => {
~>  xml2js.parseString(req.body, (err, result) => {
    if (err) return res.sendStatus(400);
    res.json(result);
  });
});

router.post('/feed2', async (req, res) => {
  const xml = req.body.xml;
~>  const result = await new xml2js.Parser().parseStringPromise(xml);
  res.json(result);
});

module.exports = router;
