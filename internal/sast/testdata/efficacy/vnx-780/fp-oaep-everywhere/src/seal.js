const crypto = require("crypto");

function seal(pub, data) {
  return crypto.publicEncrypt({ key: pub, padding: @@sample:c[r]yp[t]o[.][c]on[s]ta[n]ts[.]RS[A][_]P[K]CS[1][_]O[A]EP[_]PA[D]DI[N]G@@, oaepHash: "sha256" }, data);
}

function sealDefault(pub, data) {
  return crypto.publicEncrypt(pub, data);
}
module.exports = { seal, sealDefault };
