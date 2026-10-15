const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

exports.find = (req, res) => {
  const re = new RegExp(`^${escapeRegExp(req.query.q)}`, 'i');
  res.json(names.filter((n) => re.test(n)));
};
