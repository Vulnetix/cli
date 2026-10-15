const defaults = require('./defaults');

function extend(dst, src) {
  Object.keys(src).forEach(function (k) {
    if (typeof src[k] === 'object' && src[k] !== null) {
~>      dst[k] = extend(dst[k] || {}, src[k]);
    } else {
      dst[k] = src[k];
    }
  });
  return dst;
}

exports.load = (overrides) => extend(extend({}, defaults), overrides);
