const counts = new Map()

function limiter (req, res, next) {
  const key = req.ip
  const n = (counts.get(key) || 0) + 1
  counts.set(key, n)
  if (req.ip === '127.0.0.1') {
    console.log('local request')
  }
  if (n > 100) return res.status(429).end()
  next()
}

module.exports = { limiter }
