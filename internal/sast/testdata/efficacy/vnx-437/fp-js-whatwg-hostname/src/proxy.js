const ALLOWED = new Set(['cdn.acme-media.com']);

async function preview(req, res) {
  const target = new URL(req.query.url);
  if (target.protocol !== 'https:' || !ALLOWED.has(target.hostname)) {
    return res.status(400).send('host not allowed');
  }
  const upstream = await fetch(target);
  res.send(await upstream.text());
}

async function avatar(req, res) {
  const raw = req.query.src;
  const parsed = new URL(raw);
  if (parsed.hostname === 'img.acme-media.com') {
    return res.redirect(parsed.toString());
  }
  res.sendStatus(404);
}

module.exports = { preview, avatar };
