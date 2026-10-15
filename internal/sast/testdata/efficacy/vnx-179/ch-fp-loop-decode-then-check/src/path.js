function clean(input) {
  let value = input;
  let prev;
  do {
    prev = value;
    value = decodeURIComponent(value);
  } while (value !== prev);
  if (value.includes('..')) {
    throw new Error('traversal');
  }
  return value;
}

module.exports = { clean };
