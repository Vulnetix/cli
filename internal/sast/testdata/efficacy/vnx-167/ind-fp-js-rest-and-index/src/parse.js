function parseCredentials(decoded) {
  const i = decoded.indexOf(':');
  const user = decoded.slice(0, i);
  const pass = decoded.slice(i + 1);
  return { user, pass };
}

function parseLabel(pair) {
  const [key, ...rest] = pair.split('=');
  return { key, value: rest.join('=') };
}

function scheme(url) {
  const [proto] = url.split(':');
  return proto;
}

function fields(line) {
  const [a, b] = line.split(',');
  return { a, b };
}

// const [user, pass] = header.split(':');
const usage = "const [user, pass] = header.split(':')";

module.exports = { parseCredentials, parseLabel, scheme, fields, usage };
