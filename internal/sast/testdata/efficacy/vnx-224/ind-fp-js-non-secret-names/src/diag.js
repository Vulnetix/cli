function dumpState(passwordPolicy, tokenizerOutput, apiKeyId, avatar) {
  console.log("policy", btoa(JSON.stringify(passwordPolicy)));
  console.log("tokens", Buffer.from(tokenizerOutput).toString("base64"));
  console.info("key id", btoa(apiKeyId));
  console.debug("avatar", Buffer.from(avatar).toString("base64"));
}

module.exports = { dumpState };
