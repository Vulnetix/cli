const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com']);

async function fetchImage(req, res) {
  const target = new URL(req.query.url);
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).json({ error: 'host not allowed' });
  }
  const r = await fetch('https://' + target.hostname + '/img/logo.png');
  res.json({ size: (await r.arrayBuffer()).byteLength });
}
module.exports = fetchImage;
