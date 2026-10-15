module.exports = function search(req, res) {
  const q = String(req.query.q || '');
  const parts = q.split(' ');
  const sort = `${req.query.sort}`;
  res.json({ parts, desc: sort.startsWith('-') });
};
