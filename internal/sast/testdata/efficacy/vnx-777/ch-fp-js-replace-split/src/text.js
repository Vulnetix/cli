function strip(s) {
  const t = s.replace(/^[a-z]+/, "");
  const parts = s.split(/[0-9]+$/);
  if (/^\s+/.test(s)) {
    return t;
  }
  return parts.join("");
}
module.exports = { strip };
