const { XMLParser } = require('fast-xml-parser');
const xml2js = require('xml2js');
const sanitize = require('./sanitize');

const parser = new XMLParser({ processEntities: false });
const opts = { noent: true, trim: true };

async function parse(xml) {
  const a = parser.parse(xml);
  const b = await @@sample:x[m]l2[j]s[.][p]ar[s]eS[t]ri[n]gP[r]om[i]se@@(xml, { explicitArray: false });
  return { a, b, clean: sanitize(xml, opts) };
}

module.exports = { parse };
