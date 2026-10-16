const axios = require('axios');
const API_BASE = 'https://api.example.com/v2';

async function item(req, res) {
  const r = await axios.get(API_BASE + '/items/' + encodeURIComponent(req.params.id), {
    headers: { 'X-Trace': req.headers['x-trace-id'] },
  });
  res.json({ ok: r.status === 200 });
}
module.exports = item;
