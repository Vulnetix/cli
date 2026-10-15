const { privateDecrypt, constants } = require("crypto");

function open(privateKey, buf) {
  return privateDecrypt(
    {
      key: privateKey,
~>      padding: @@sample:c[o]ns[t]an[t]s[.][R]SA[_]PK[C]S1[_]PA[D]DI[N]G@@,
    },
    buf,
  );
}
module.exports = { open };
