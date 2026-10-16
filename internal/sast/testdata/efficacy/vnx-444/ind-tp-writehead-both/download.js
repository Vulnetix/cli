const fs = require('fs');

function serveExport(req, res, filePath) {
  const stat = fs.statSync(filePath);
~>  res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Length': stat.size, 'Transfer-Encoding': 'chunked' });
  fs.createReadStream(filePath).pipe(res);
}

module.exports = { serveExport };
