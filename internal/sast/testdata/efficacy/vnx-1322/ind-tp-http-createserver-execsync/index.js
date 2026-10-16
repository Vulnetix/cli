const http = require('http');
const { execSync } = require('child_process');
http.createServer((req, res) => {
~>  const out = execSync('df -h').toString();
  res.writeHead(200);
  res.end(out);
}).listen(8080);
