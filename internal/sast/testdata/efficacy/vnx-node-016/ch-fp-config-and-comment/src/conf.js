const config = require('./config');
// new RegExp(req.query.q) would let a client choose the pattern
const allow = new RegExp(config.allowedOriginPattern);
const doc = 'do not write new RegExp(req.body.re)';
module.exports = { allow, doc };
