function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function esc2(s) { return s.replaceAll('<', '&lt;'); }
module.exports = { esc, esc2 };
