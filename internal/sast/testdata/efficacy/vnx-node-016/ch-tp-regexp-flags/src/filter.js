exports.filter = (req, res) => {
~>  const re = new RegExp(req.query.q, 'i');
  res.json(items.filter((i) => re.test(i.name)));
};
