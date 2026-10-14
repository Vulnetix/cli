const http = require('http');

http.createServer((req, res) => {
  const sessionId = createSession();
~>  res.setHeader('Set-Cookie', `sessionId=${sessionId}; Path=/; Secure`);
  res.setHeader('Set-Cookie', `theme=dark; Path=/`);
  res.end('ok');
}).listen(3000);
