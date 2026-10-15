const crypto = require('crypto')

function requireService (req, res, next) {
  const given = Buffer.from(req.headers['x-service-key'] || '')
  const expected = Buffer.from(process.env.SERVICE_KEY)
  if (given.length === expected.length && crypto.timingSafeEqual(given, expected)) {
    return next()
  }
  if (req.query.lang === 'en') {
    res.locals.lang = 'en'
  }
  res.status(401).end()
}

module.exports = { requireService }
