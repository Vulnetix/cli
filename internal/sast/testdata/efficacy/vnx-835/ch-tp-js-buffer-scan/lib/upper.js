'use strict';

function shout(buf) {
  const out = [];
  let pos = 0;
~>  while (pos < buf.length) {
    const ch = buf[pos];
    out.push(ch.toUpperCase());
  }
  return out.join('');
}

module.exports = { shout };
