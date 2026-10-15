const fs = require('fs')
const { stringify } = require('csv-stringify/sync')

function record (req, res) {
  fs.appendFileSync('audit.csv', stringify([[req.body.user, req.body.action]]))
  const who = req.query.who.replace(/[\t\r\n]/g, ' ')
  fs.appendFileSync('visits.tsv', JSON.stringify(who) + '\n')
  res.send('ok')
}
