import http from 'http';

http.createServer((req, res) => {
  const url = req.url;
~>  if (url === '/admin/users' && !authorized(req)) {
    res.statusCode = 401;
    return res.end('unauthorized');
  }
  route(req, res);
}).listen(3000);
