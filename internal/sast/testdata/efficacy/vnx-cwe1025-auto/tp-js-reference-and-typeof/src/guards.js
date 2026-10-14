'use strict';

function requireRoles(user) {
~>  if (user.roles === []) {
    throw new Error('no roles');
  }
~>  if (user.constructor.name === 'Admin') {
    return true;
  }
  return false;
}

function validFilter(filter) {
~>  if (typeof filter === 'array') {
    return filter.length > 0;
  }
~>  return typeof(filter) !== "null" && filter != {};
}

module.exports = { requireRoles, validFilter };
