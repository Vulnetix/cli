const passport = require("passport");
const { DigestStrategy } = require("passport-http");
const httpntlm = require("httpntlm");
const DigestFetch = require("digest-fetch");
const { NtlmClient } = require("axios-ntlm");

~>passport.use(new DigestStrategy({ qop: "auth" }, (username, done) => {
  findUser(username, done);
}));

function legacyShare(url) {
~>  httpntlm.get({ url, username: process.env.U, password: process.env.P, domain: "CORP" }, cb);
}

~>const client = new DigestFetch(process.env.U, process.env.P);
~>const ntlm = NtlmClient({ username: process.env.U, password: process.env.P, domain: "CORP" });

module.exports = { legacyShare, client, ntlm };
