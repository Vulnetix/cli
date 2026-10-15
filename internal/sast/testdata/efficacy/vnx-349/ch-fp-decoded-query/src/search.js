function search(req, res) {
  const decodedQuery = {};
  for (const [k, v] of Object.entries(req.query)) {
    decodedQuery[k] = decodeURIComponent(v);
  }
  Object.assign(decodedQuery, req.query);
  res.json(runSearch(decodedQuery));
}

module.exports = { search };
