function canManage(user) {
~>  if (user.role.includes('admin')) {
    return true;
  }
  return false;
}
