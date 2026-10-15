function canDelete(req, user) {
  if (req.user.role === 'admin') {
    return true;
  }
  if (user.roles.includes('admin')) {
    return true;
  }
  if (req.session.role === 'admin') {
    return true;
  }
  if ((user.role = lookupRole(user.id)) !== null) {
    return user.role === 'owner';
  }
  return false;
}

module.exports = { canDelete };
