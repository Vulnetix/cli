const libxmljs = require('libxmljs');

// Do not pass { noent: true } here: it expands external entities (XXE).
const WARNING = 'noent: true enables entity substitution';

/*
 * libxmljs.parseXml(xml, { noent: true })
 */
function parse(xml) {
  return libxmljs.parseXml(xml, { nonet: true });
}

module.exports = { parse, WARNING };
