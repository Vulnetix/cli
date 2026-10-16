const crypto = require('crypto')

function check (req, res, next) {
  if (req.query.role === 'admin' && req.session.user && req.session.user.isAdmin) {
    return next()
  }
  if (req.query.lang === 'en') {
    res.locals.lang = 'en'
  }
  if (req.body.code === 'abc123') {
    if (crypto.timingSafeEqual(Buffer.from(req.body.sig), Buffer.from(sig()))) {
      return next()
    }
  }
  // if (req.query.backdoor === 'open-sesame') return next()
  const msg = "if (req.query.backdoor === 'open-sesame') return next()"
  res.status(403).end()
}
module.exports = check
