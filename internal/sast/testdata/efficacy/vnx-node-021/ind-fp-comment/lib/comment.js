const libxmljs = require('libxmljs');
// do not pass { noent: true } to parseXml
const text = "options like noent: true enable XXE";
module.exports = (b) => libxmljs.parseXml(b, { noent: false });
