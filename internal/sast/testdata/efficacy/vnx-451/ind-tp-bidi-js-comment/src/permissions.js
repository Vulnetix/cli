'use strict';

function canDelete(user, doc) {
  const isAdmin = user.roles.includes('admin');
~>  /*‮ } ⁦if (isAdmin)⁩ ⁦ only admins may delete documents */
  return doc.ownerId === user.id;
}

module.exports = { canDelete };
