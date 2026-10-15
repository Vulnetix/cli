const ADMIN_ROLES = ['admin', 'owner'];

function canManage(user) {
  return ADMIN_ROLES.includes(user.role);
}

function isAdmin(user) {
  return user.role === 'admin';
}

module.exports = { canManage, isAdmin };
