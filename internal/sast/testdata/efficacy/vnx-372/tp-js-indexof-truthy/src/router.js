function isApi(url) {
~>  if (url.indexOf('/api/')) {
    return true;
  }
  return false;
}

function hasRole(user, role) {
~>  return user && user.roles.indexOf(role) ? 'yes' : 'no';
}

module.exports = function guard(req, res, next) {
  const path = req.path;
~>  if (req.method === 'POST' && path.lastIndexOf('/upload')) {
    return next();
  }
~>  if (path.indexOf('admin') == true) {
    res.status(403).end();
  }
  next();
};
