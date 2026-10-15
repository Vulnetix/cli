// if (false) { old(); }
/* return x;
   unreachable(); */
const hint = "if (false) { } is dead code";
function f(x) {
  // return early
  // return x;
  return x;
}
