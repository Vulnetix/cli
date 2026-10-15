function parseRoles(text) {
  const out = [];
  const re = /role=(\w+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push(m[1]);
  }
  let role;
  if ((role = out[0])) {
    return role;
  }
  return null;
}

module.exports = { parseRoles };
