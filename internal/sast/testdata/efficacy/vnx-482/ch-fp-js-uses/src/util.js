const isOne = (x) => x === 1;
const same = (a, b) =>
  a === b;

function check(a, b) {
  const ok = a == b;
  if (a === b) return ok;
  expect(a === b).toBe(true);
  return a !== b
    && ok;
}

module.exports = { isOne, same, check };
