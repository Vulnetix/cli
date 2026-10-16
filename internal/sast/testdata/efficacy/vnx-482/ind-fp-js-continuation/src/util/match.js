function same(a, b) {
  const result =
    a.id === b.id &&
    a.version === b.version;
  if (a.kind === 'x') return result;
  return result ? a.name === b.name : false;
}

module.exports = { same };
