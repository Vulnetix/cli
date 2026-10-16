function clean(p) {
  return p.replace(/\.\.\//g, '').replaceAll('..', '');
}
function price(s) { return s.replace('$', ''); }
function css(v) { return v.replace(';', ''); }
module.exports = { clean, price, css };
