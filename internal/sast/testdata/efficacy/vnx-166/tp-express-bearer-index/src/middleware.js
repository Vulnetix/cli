const jwt = require('jsonwebtoken')

function requireAuth (req, res, next) {
~>  const token = req.headers.authorization.split(' ')[1]
  req.user = jwt.verify(token, process.env.JWT_SECRET)
  next()
}

function locale (req, res, next) {
  const tag = req.query.lang
~>  req.region = tag.split('-')[1].toUpperCase()
  next()
}

module.exports = { requireAuth, locale }
