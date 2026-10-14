const libxmljs = require('libxmljs');

function parse(body) {
  // Entities are left unexpanded: noent defaults to false.
  return libxmljs.parseXml(body, { noent: false, nonet: true });
}

function parseDefault(body) {
  return libxmljs.parseXmlString(body);
}

const help = 'never pass { noent: true } to parseXml';

module.exports = { parse, parseDefault, help };
