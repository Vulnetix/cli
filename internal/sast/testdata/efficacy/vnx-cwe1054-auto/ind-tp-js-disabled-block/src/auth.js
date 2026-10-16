function check(req, res, next) {
~>  // if (!req.session.user) {
  //   return res.status(401).send('no');
  // }
  // const role = req.session.user.role;
  next();
}
