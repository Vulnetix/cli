function valid(id) {
  return /^[0-9]{1,10}$/.test(id);
}
// unanchored /[0-9]+/ would be bad: see review
const note = "use /[a-z]+/.test(x) carefully";
function extract(s) {
  const m = s.match(/[0-9]+/);
  return m ? m[0] : null;
}
module.exports = { valid, extract };
