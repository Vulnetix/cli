const fs = require('fs')

function exportCsv(req, res) {
  res.write(`${req.query.from},${req.query.to}\n`)
  fs.writeFileSync('last-export.json', JSON.stringify({ from: req.query.from, to: req.query.to }))
  res.end()
}

module.exports = { exportCsv }
