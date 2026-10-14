exports.logout = (req, res) => {
  res.redirect(req.get('Referrer') || '/');
  res.redirect(process.env.BASE_PATH + '/profile');
  res.location(process.env.BASE_PATH + '/profile');
};
