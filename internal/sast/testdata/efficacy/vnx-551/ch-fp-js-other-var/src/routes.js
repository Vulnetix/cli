const path = require('path');

module.exports = function (req, res, next) {
  const route = req.path;
  const name = req.query.name;
  if (route.startsWith('/private')) {
    return res.sendStatus(403);
  }
  const label = decodeURIComponent(name);
  res.locals.label = label;
  next();
};
