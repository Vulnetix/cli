class MyDigestStrategyConfig {}
const digest = crypto.createHash("sha256").update(body).digest("hex");
const scheme = "ntlmAuthDisabled";
function isNtlmRequest(req) { return req.headers.authorization === undefined; }
module.exports = { MyDigestStrategyConfig, digest, scheme, isNtlmRequest };
