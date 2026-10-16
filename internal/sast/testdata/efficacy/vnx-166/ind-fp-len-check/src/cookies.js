function sessionInfo(req, res) {
  const parts = req.cookies.session.split('|')
  if (parts.length !== 2) {
    return res.status(400).end()
  }
  const expires = new Date(parts[1])
  res.json({ expires })
}

module.exports = { sessionInfo }
