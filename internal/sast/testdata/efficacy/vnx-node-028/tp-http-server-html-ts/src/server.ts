import http from 'http';
import { renderPage } from './render';

~>const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(renderPage(req.url ?? '/'));
});

server.listen(3000);
