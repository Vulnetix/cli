function setSid(res, sid) {
~>  res.setHeader('Set-Cookie', 'sid=' + sid + '; HttpOnly; Secure; SameSite=None');
}
module.exports = { setSid };
