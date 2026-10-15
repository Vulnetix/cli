const deepExtend = require("deep-extend");

function importConfig(req, base) {
  const incoming = JSON.parse(req.body.config);
~>  return deepExtend(base, incoming);
}

module.exports = { importConfig };
