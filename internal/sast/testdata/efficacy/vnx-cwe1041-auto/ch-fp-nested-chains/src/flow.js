function route(user, req) {
  if (user.isAdmin) {
    if (req.method === 'GET') {
      return 'read';
    } else if (req.method === 'POST') {
      return 'write';
    }
  } else if (user.isGuest) {
    if (req.method === 'GET') {
      return 'read-guest';
    } else if (req.method === 'HEAD') {
      return 'head';
    }
  }
  if (user.isAdmin) {
    return 'admin';
  }
  else if (user.isOwner) {
    return 'owner';
  }
  return 'none';
}
module.exports = { route };
