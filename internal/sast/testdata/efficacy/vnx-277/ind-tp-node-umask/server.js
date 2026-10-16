const http = require('http');

~>process.umask(0);
http.createServer((req, res) => res.end('ok')).listen(8080);
