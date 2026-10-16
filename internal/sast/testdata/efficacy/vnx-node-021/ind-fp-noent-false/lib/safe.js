const libxmljs = require('libxmljs');
function parse(body) {
  return libxmljs.parseXml(body, { noent: false, nonet: true });
}
function parse2(body) {
  return libxmljs.parseXml(body);
}
module.exports = { parse, parse2 };
