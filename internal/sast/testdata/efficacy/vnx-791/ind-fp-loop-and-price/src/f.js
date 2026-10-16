function strip(input) {
  let prev;
  do {
    prev = input;
    input = input.replace(/<script>/gi, '');
  } while (input !== prev);
  return input;
}
function money(p) { return p.replace('$', ''); }
function ellipsis(s) { return s.replace('..', '...'); }
module.exports = { strip, money, ellipsis };
