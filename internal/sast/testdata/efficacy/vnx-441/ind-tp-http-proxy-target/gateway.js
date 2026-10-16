const http = require('http');
const express = require('express');
const httpProxy = require('http-proxy');

const app = express();
const proxy = httpProxy.createProxyServer({ changeOrigin: true });

app.use('/forward', (req, res) => {
~>  proxy.web(req, res, { target: req.query.upstream });
});

http.createServer(app).listen(8080);
