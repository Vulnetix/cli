const HOST_RE = /^[a-z0-9.-]+/i

function validHost (host) {
~>  return HOST_RE.test(host)
}

function checkId (req, res, next) {
~>  if (!/[0-9]{1,10}$/.test(req.params.id)) {
    return res.status(400).end()
  }
  next()
}

function checkToken (token) {
~>  if (!token.match(/^[A-Fa-f0-9]{32}/)) throw new Error('bad token')
}

module.exports = { validHost, checkId, checkToken }
