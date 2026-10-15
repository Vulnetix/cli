async function waitForJob(api, id) {
  let status = 'queued';
  while (status !== 'done') {
    status = await api.status(id);
  }
}

function fib(n) {
  let a = 0;
  let b = 1;
  let i = 0;
  while (i < n) {
    [a, b] = [b, a + b];
    i++;
  }
  return a;
}

function skipSpaces(s, i) {
  while (i < s.length) {
    if (s[i] !== ' ') {
      return i;
    }
    ++i;
  }
  return i;
}

module.exports = { waitForJob, fib, skipSpaces };
