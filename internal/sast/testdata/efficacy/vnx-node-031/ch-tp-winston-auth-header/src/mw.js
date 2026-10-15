const winston = require('winston');

module.exports = (req, res, next) => {
~>  winston.info('incoming request', { path: req.path, auth: req.headers.authorization });
  next();
};
