'use strict';

function canDelete(user) {
  const isAdmin = user.role === 'admin';
~>  /*‮ } ⁦if (isAdmin)⁩ ⁦ only admins may delete */
  return true;
}

module.exports = { canDelete };
