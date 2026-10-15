const Web3 = require("web3");
const web3 = new Web3(process.env.RPC_URL);

~>@@sample:w[e]b3[.]et[h][.]a[c]co[u]nt[s][.]w[a]ll[e]t[.][a]dd@@("0x@@sample:[0-9a-f]{64}@@");

async function send(tx) {
~>  const signed = await @@sample:w[e]b3[.]et[h][.]a[c]co[u]nt[s][.]s[i]gn[T]ra[n]sa[c]ti[o]n@@(tx, "0x@@sample:[0-9a-f]{64}@@");
  return @@sample:w[e]b3[.]et[h][.]s[e]nd[S]ig[n]ed[T]ra[n]sa[c]ti[o]n@@(signed.rawTransaction);
}
