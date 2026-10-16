const DEFAULT_RANGE = '2024-01-01|2024-12-31'

function bearer(req) {
  const h = req.headers.authorization || ''
  if (!h.includes(' ')) return null
  return h.split(' ')[1]
}

function defaultEnd() {
  return DEFAULT_RANGE.split('|')[1]
}

module.exports = { bearer, defaultEnd }
