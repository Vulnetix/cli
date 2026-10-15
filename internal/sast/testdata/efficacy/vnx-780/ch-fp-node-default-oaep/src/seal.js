const crypto = require("crypto");

function seal(pub, buf) {
  return crypto.publicEncrypt(pub, buf);
}

function sealOaep(pub, buf) {
  return crypto.publicEncrypt({ key: pub, padding: @@sample:c[r]yp[t]o[.][c]on[s]ta[n]ts[.]RS[A][_]P[K]CS[1][_]O[A]EP[_]PA[D]DI[N]G@@, oaepHash: "sha256" }, buf);
}
module.exports = { seal, sealOaep };
