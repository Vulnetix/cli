const libxmljs2 = require('libxmljs2');
function parse(xml) {
  return libxmljs2.parseXmlString(xml, {
    nonet: false,
~>    noent: true,
    dtdload: true,
  });
}
module.exports = parse;
