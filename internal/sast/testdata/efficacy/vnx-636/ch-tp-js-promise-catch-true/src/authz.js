async function isAllowed(user, action) {
~>  return opa.evaluate({ user, action }).then((r) => r.allow).catch(() => true);
}

function canDelete(user, doc) {
~>  return policy.check(user, "delete", doc).catch(err => true);
}

module.exports = { isAllowed, canDelete };
