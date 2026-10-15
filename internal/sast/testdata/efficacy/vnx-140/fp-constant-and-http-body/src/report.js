const fs = require('fs')

function report (req, res, rows) {
  fs.writeFileSync('header.csv', 'id,name,email\n')
  res.write(`${req.query.a},${req.query.b}\n`)
  for (const r of rows) {
    fs.appendFileSync('rows.csv', `${r.id},${r.name}\n`)
  }
  res.end()
}
