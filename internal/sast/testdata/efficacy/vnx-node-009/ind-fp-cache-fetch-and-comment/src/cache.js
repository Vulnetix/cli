const cache = require('./cache-store');

function lookup(req, res) {
  // fetch(req.query.url) would be dangerous; we only read the local cache
  const hit = cache.fetch(req.query.key);
  const note = "axios.get(req.query.url) is not used here";
  res.json({ hit, note });
}
module.exports = lookup;
