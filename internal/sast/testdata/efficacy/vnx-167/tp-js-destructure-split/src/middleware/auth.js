function basicAuth(req) {
  const b64 = (req.headers.authorization || '').replace('Basic ', '');
~>  const [user, pass] = Buffer.from(b64, 'base64').toString().split(':');
  return { user, pass };
}

function cookieValue(cookie) {
~>  let [name, value] = cookie.split('=');
  return { name, value };
}

function setting(line) {
  let k, v;
~>  [k, v] = line.split("=", 2);
  return { k, v };
}

module.exports = { basicAuth, cookieValue, setting };
