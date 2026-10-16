const qs = require("qs");

module.exports = function parseFilters(req, res, next) {
  const raw = req.originalUrl.split("?")[1] || "";
~>  req.filters = qs.parse(raw, { depth: 100, allowDots: true });
  next();
};
