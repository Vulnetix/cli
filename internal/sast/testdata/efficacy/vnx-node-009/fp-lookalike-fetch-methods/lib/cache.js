const LRU = require('lru-cache');

const cache = new LRU({ max: 500 });

function lookup(req, res) {
  const entry = cache.fetch(req.params.key);
  const item = store.get(req.query.id);
  const row = repository.request(req.body.name);
  res.json({ entry, item, row });
}

function prefetchAll(req, res) {
  prefetch(req.query.ids);
  res.end();
}

module.exports = { lookup, prefetchAll };
