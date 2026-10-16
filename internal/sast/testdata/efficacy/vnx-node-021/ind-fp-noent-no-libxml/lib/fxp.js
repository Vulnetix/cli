const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ ignoreAttributes: false, noent: true });
module.exports = (x) => parser.parse(x);
