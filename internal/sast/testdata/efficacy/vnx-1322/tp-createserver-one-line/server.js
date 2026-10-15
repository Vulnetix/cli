const http = require('http')
const fs = require('fs')

~>http.createServer((req, res) => res.end(fs.readFileSync(__dirname + '/index.html'))).listen(8080)
