module.exports = function dashboard(req, res) {
~>  switch (req.headers['x-user-role']) {
    case 'admin':
      return res.render('admin-dashboard');
    default:
      return res.render('dashboard');
  }
};
