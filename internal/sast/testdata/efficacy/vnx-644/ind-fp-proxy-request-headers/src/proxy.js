const http = require('http');
const httpProxy = require('http-proxy');

const proxy = httpProxy.createProxyServer({ target: 'http://backend:8080' });

http.createServer((req, res) => {
  req.headers['x-forwarded-host'] = req.headers.host;
  req.headers['x-original-uri'] = req.url;
  proxy.web(req, res);
}).listen(8000);
