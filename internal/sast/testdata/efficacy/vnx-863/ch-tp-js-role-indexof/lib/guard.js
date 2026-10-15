function canManage(user) {
~>  if (user.role.indexOf('admin') !== -1) {
    return true;
  }
  return false;
}

module.exports = { canManage };
