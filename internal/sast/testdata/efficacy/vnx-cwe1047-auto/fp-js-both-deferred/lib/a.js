function useB() {
  const b = require('./b');
  return b.value();
}

module.exports = { useB, value: () => 1 };
