function check(header, tokenType) {
  if (header.signatureAlgorithm === "RS256") return true;
  if (tokenType === "Bearer") return true;
  if (header.alg === "none") return false;
  return false;
}
module.exports = { check };
