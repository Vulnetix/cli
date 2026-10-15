const libxmljs = require('libxmljs');

module.exports = function importFeed(req, res) {
  const doc = libxmljs.parseXmlString(req.body.toString(), { noent: false, nonet: true });
  const plain = libxmljs.parseXml(req.body.toString());
  res.json({ a: doc.root().name(), b: plain.root().name() });
};
