const http = require('http');
const cookie = require('cookie');

http.createServer((req, res) => {
  const sid = makeSid();
~>  res.setHeader('Set-Cookie', `session=${sid}; Path=/; Secure; SameSite=Lax`);
  res.end('ok');
}).listen(3000);

function other(res, token) {
~>  res.setHeader('Set-Cookie', cookie.serialize('access_token', token, { path: '/', secure: true }));
}
