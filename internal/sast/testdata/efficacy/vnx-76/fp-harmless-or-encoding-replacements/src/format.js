function format(s, url) {
  const slug = s.replace(/\s+/g, '').replace('-', '');
  const safe = s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const secure = url.replace('http://', 'https://');
  // never: s.replace('<script>', '')
  const note = "use s.replace('<script>', '') only in tests";
  return [slug, safe, secure, note];
}
module.exports = format;
