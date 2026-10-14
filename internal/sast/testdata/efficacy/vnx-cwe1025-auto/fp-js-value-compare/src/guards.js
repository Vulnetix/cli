'use strict';

function requireRoles(user) {
  if (Array.isArray(user.roles) && user.roles.length === 0) {
    throw new Error('no roles');
  }
  if (user instanceof Admin) {
    return true;
  }
  const empty = {};
  if (typeof user.name === 'string' && typeof user.id === "number" && typeof cb == 'function') {
    return Object.keys(user.meta || empty).length === 0;
  }
  // user.roles === [] is always false
  const msg = "use Array.isArray, not x === []";
  return typeof user.created === 'object' && typeof user.big === 'bigint' && msg;
}

module.exports = { requireRoles };
