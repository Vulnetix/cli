const qs = require("qs");

function parseFilters(rawQuery) {
~>  return qs.parse(rawQuery, { arrayLimit: Number.MAX_SAFE_INTEGER });
}

module.exports = { parseFilters };
