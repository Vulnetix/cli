const http = require('http');

http.createServer((req, res) => {
  const id = newSessionId();
~>  res.setHeader('Set-Cookie', [`session=${id}; Path=/; Secure`, 'theme=dark']);
  res.writeHead(200, {
~>    'Set-Cookie': `auth_token=${issue(id)}; Path=/`,
    'Content-Type': 'text/plain',
  });
  res.end('ok');
}).listen(8080);
