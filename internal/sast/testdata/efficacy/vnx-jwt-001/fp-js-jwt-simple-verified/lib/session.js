const jwt = require('jwt-simple');

exports.load = function (req) {
  return jwt.decode(req.get('X-Auth'), process.env.SESSION_SECRET);
};

exports.loadStrict = (req) => jwt.decode(req.query.t, process.env.SESSION_SECRET, false, 'HS512');
