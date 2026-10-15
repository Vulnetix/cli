exports.byPrefix = (req, res) => {
  const pattern = req.body.prefix;
~>  const re = new RegExp('^' + pattern + '.*$');
  res.json(names.filter((n) => re.test(n)));
};
