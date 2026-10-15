const fs = require('fs')

function record (req, res) {
~>  fs.appendFileSync('audit.csv', `${req.body.user},${req.body.action}\n`)
  const who = req.query.who
~>  fs.appendFile('visits.tsv', who + '\t' + Date.now() + '\n', () => {})
  res.send('ok')
}

module.exports = { record }
