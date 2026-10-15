exports.grep = (req, res) => {
  const { pattern } = req.query;
~>  const hits = [...logText.matchAll(pattern)];
  res.json(hits.length);
};
