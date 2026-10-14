const axios = require('axios');

const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com']);

async function preview(req, res) {
  const target = new URL(req.query.url);
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).send('host not allowed');
  }
  const page = await axios.get(target.toString());
  return res.send(page.data);
}

module.exports = { preview };
