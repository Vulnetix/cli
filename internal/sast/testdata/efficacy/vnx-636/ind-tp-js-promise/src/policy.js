function canAccess(user, doc) {
~>  return policyEngine.check(user, doc).catch(() => true);
}
module.exports = { canAccess };
