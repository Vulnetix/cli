const axios = require('axios');

async function search(req, res) {
  const r = await axios.get('https://search.example.com/api', {
    params: { q: req.query.q, page: req.query.page },
  });
  res.json({ total: r.data.total });
}
module.exports = search;
