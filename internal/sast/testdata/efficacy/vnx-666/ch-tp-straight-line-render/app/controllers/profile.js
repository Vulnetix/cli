exports.show = function (req, response) {
  const viewModel = { name: req.user.name };
~>  response.render('profile', viewModel);
  response.redirect('/dashboard');
};
