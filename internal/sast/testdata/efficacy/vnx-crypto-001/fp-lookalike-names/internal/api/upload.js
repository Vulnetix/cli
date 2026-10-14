const crypto = require('crypto')

function verify (file, meta) {
  const reported = meta.md5(file)
  const ours = crypto.createHash('sha256').update(file).digest('hex')
  return { reported, ours, md5Header: file.headers['content-md5'] }
}

module.exports = { verify }
