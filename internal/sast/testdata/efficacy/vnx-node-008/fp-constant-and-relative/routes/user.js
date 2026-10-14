exports.show = (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.redirect('/users/' + req.params.id);
  res.redirect(`/pets/${req.query.pet}`);
  window.location.href = '/dashboard';
};
