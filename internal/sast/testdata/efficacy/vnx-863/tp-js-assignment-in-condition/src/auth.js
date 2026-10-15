function authorize(user, action) {
~>  if (user.role = 'admin') {
    return true;
  }
  return action === 'read';
}

function adminOnly(req, res, next) {
~>  if (req.user.isAdmin = true) return next();
  res.sendStatus(403);
}

module.exports = { authorize, adminOnly };
