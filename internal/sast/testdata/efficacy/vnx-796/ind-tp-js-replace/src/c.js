function clean(name) {
~>  const c = name.replace(/^(\.\.\/)+/, '');
  return c;
}
module.exports = clean;
