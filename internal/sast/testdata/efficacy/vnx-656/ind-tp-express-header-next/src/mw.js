function support (req, res, next) {
~>  if (req.headers['x-support-key'] === 'zx81-open-sesame') {
    return next()
  }
  res.status(401).end()
}
module.exports = support
