const tls = require("tls");
const server = tls.createServer({
  ciphers: "@@sample:E[C]DH[E][-]R[S]A[-][A]ES[1]28[-]GC[M][-]S[H]A2[5]6@@:!DES:!RC4:!3DES",
  minVersion: "TLSv1.2",
});
module.exports = server;
