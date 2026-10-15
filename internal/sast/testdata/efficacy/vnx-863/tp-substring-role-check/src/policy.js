function canDelete(user) {
~>  if (user.role.includes('admin')) {
    return true;
  }
~>  return user.role.indexOf("superuser") !== -1;
}

function isModerator(req) {
~>  return /moderator/.test(req.user.role);
}

module.exports = { canDelete, isModerator };
