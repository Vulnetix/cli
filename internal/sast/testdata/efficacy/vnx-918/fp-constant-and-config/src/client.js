const axios = require('axios');

router.get('/users/:id', async (req, res) => {
  const r = await axios.get(`${config.apiUrl}/users/${req.params.id}`);
  const s = await fetch('https://status.example.com/health');
  const q = await axios.get(API_URL, { params: { q: req.query.q } });
  res.json([r.data, s.ok, q.data]);
});
