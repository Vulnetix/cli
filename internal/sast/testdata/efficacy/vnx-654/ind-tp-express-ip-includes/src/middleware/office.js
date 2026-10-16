const OFFICE = ['203.0.113.10', '203.0.113.11']

function officeOnly (req, res, next) {
~>  if (OFFICE.includes(req.ip)) {
    return next()
  }
  res.status(403).send('forbidden')
}

module.exports = officeOnly
