const BLOCKED = ['198.51.100.7']
const log = require('./log')

function guard (req, res, next) {
  if (BLOCKED.includes(req.ip)) {
    return res.status(403).end()
  }
  log.info('request from ' + req.ip)
  if (req.ip !== '127.0.0.1') {
    return res.status(401).end()
  }
  return next()
}

module.exports = guard
