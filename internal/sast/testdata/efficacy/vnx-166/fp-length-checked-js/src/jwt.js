function jwtFrom (req) {
  if (req.headers.authorization) {
    const parts = req.headers.authorization.split(' ')
    if (parts.length === 2) {
      const token = parts[1]
      return token
    }
  }
  return null
}

function region (req) {
  const tag = req.query.lang || ''
  if (!tag.includes('-')) return 'US'
  return tag.split('-')[1]
}

function last (req) {
  return req.path.split('/').pop()
}

module.exports = { jwtFrom, region, last }
