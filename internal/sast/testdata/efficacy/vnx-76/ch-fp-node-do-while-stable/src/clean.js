function clean(s) {
  let prev;
  do {
    prev = s;
    s = s.replace(/\.\.\//g, "");
  } while (s !== prev);
  return s;
}

function nl(s) {
  return s.replace(/\n/g, "");
}

module.exports = { clean, nl };
