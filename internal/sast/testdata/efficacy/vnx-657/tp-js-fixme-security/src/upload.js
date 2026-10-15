const fs = require('fs')

function save (req, res) {
~>  // FIXME: security - file name is not sanitized
  fs.writeFileSync('/srv/uploads/' + req.query.name, req.body)
~>  // XXX insecure: TLS verification disabled temporarily
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  res.end()
}

module.exports = { save }
