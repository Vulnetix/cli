const jwt = require('jsonwebtoken')

module.exports = function requireAuth(req, res, next) {
~>  const token = req.headers.authorization.split(' ')[1]
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET)
  } catch (err) {
    return res.status(401).end()
  }
  next()
}
