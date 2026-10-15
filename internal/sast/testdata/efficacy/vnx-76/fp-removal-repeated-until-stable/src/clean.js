function cleanPath(s) {
  while (s.includes('../')) {
    s = s.replace('../', '');
  }
  return s;
}
module.exports = cleanPath;
