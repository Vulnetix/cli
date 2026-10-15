const libxmljs = require('libxmljs');

module.exports = function importFeed(req, res) {
~>  const doc = libxmljs.parseXmlString(req.body.toString(), { noent: true, noblanks: true });
  res.json({ items: doc.find('//item').length });
};
