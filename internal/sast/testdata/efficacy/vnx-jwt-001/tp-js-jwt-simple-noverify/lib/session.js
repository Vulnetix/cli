const jwt = require('jwt-simple');

exports.load = function (req) {
  const raw = req.get('X-Auth');
~>  return jwt.decode(raw, process.env.SESSION_SECRET, true);
};

exports.loadHs = (req) =>
~>  jwt.decode(req.query.t, process.env.SESSION_SECRET, true, 'HS512');
