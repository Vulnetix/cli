'use strict';
const http = require('http');
const finalhandler = require('finalhandler');
const serveStatic = require('serve-static');

const webRoot = process.cwd();

~>const serve = serveStatic(webRoot, { index: ['index.html'], dotfiles: 'allow' });

const server = http.createServer((req, res) => {
  serve(req, res, finalhandler(req, res));
});

server.listen(8080);
