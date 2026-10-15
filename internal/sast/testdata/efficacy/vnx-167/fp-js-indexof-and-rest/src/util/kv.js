function pair(s) {
  const i = s.indexOf('=');
  return [s.slice(0, i), s.slice(i + 1)];
}

function withRest(s) {
  const [key, ...rest] = s.split('=');
  return [key, rest.join('=')];
}

function first(s) {
  const [name] = s.split('=');
  return name;
}

function csv(s) {
  const [a, b] = s.split(',');
  return a + b;
}

module.exports = { pair, withRest, first, csv };
