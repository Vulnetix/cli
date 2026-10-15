const axios = require('axios');
const API_BASE = process.env.CATALOG_API;

exports.search = async (req, res) => {
  const r = await axios.get('https://catalog.internal.example.com/items', {
    params: { q: req.query.q, page: req.query.page },
  });
  const item = await fetch(`${API_BASE}/items/${encodeURIComponent(req.params.id)}`);
  res.json({ results: r.data, item: await item.json() });
};
