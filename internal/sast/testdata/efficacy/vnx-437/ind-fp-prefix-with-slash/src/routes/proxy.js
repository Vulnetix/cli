const axios = require('axios');

async function proxyImage(req, res) {
  const target = String(req.query.src || '');
  if (!target.startsWith('https://images.acme-cdn.com/')) {
    return res.status(400).end();
  }
  const upstream = await axios.get(target, { responseType: 'stream' });
  upstream.data.pipe(res);
}
