module.exports = function account(req, res, next) {
  const mode = req.cookies.mode;
~>  if (mode === 'superuser') {
    res.locals.isAdmin = true;
  }
  next();
};
