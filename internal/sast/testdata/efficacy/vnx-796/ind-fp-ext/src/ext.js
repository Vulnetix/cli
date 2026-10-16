function base(name) {
  return name.replace(/\.[^/.]+$/, '');
}
function slug(s) { return s.replace(/-+/g, '-'); }
module.exports = { base, slug };
