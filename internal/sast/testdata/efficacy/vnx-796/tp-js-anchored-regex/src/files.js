const path = require('path');

function resolve(name) {
~>  const clean = name.replace(/^(\.\.\/)+/, '');
  return path.join('/srv/files', clean);
}

function resolve2(name) {
~>  return path.join('/srv', name.replace(/^\.+\//g, ''));
}
