const libxmljs = require('libxmljs');

function parse(body) {
~>  return libxmljs.parseXml(body, { noent: true });
}
module.exports = parse;
