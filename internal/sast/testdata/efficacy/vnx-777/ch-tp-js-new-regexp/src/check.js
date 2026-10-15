function validToken(tok) {
~>  return new RegExp("^[A-Za-z0-9]+").test(tok);
}

function validYear(y) {
~>  if (!RegExp('\\d{4}$', 'u').test(y)) {
    return false;
  }
  return new RegExp("^\\d{4}$").test(y);
}
module.exports = { validToken, validYear };
