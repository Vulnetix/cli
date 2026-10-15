const _ = require("lodash");

function canEdit(user, doc) {
~>  return user.roles.indexOf("editor") && doc.editable;
}

function hasOwner(users, id) {
~>  if (_.findIndex(users, (u) => u.id === id)) {
    return true;
  }
  return false;
}

module.exports = { canEdit, hasOwner };
