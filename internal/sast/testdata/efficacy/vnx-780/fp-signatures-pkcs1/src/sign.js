const crypto = require("crypto");

function sign(key, data) {
  return crypto.sign("sha256", data, { key, padding: @@sample:c[r]yp[t]o[.][c]on[s]ta[n]ts[.]RS[A][_]P[K]CS[1][_]P[A]DD[I]NG@@ });
}

function verify(key, data, sig) {
  return crypto.verify("sha256", data, { key: key, padding: @@sample:c[r]yp[t]o[.][c]on[s]ta[n]ts[.]RS[A][_]P[K]CS[1][_]P[A]DD[I]NG@@ }, sig);
}
module.exports = { sign, verify };
