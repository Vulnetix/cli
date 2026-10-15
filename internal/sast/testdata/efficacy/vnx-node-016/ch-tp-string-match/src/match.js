exports.check = (req, res) => {
~>  const found = req.app.locals.text.match(req.query.re);
  res.json({ found: !!found });
};
