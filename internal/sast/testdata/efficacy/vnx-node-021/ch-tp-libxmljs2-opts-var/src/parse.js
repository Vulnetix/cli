const libxml = require('libxmljs2');

const PARSE_OPTS = {
  dtdload: true,
~>  noent: true,
};

function parse(xml) {
  return libxml.parseXml(xml, PARSE_OPTS);
}

module.exports = { parse };
