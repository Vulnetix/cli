const memoize = require("memoize-one");

const getRoleLabel = memoize((role) => ROLE_LABELS[role]);
const canHandle = memoize((mime) => HANDLERS.has(mime));
// const isAdmin = memoize(checkAdmin) was removed

module.exports = { getRoleLabel, canHandle };
