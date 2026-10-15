function mergeInto(target, source) {
  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(target, key) && typeof target[key] !== 'undefined') {
      throw new Error('unsafe key');
    }
    target[key] = source[key];
  }
  return target;
}

function nullMerge(source) {
  const target = Object.create(null);
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

module.exports = { mergeInto, nullMerge };
