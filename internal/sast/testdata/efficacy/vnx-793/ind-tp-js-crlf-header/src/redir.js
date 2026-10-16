function redirect(res, target) {
~>  res.setHeader('Location', target.replace('\r\n', ''));
  res.statusCode = 302;
}
module.exports = redirect;
