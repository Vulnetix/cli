const ALLOWED = new Set(['cdn.acme-media.com']);

async function preview(req, res) {
  const link = req.body.link;
  if (link.includes('metadata.google.internal')) {
    return res.status(400).end();
  }
  const parsed = new URL(link);
  if (!ALLOWED.has(parsed.hostname)) {
    return res.status(403).end();
  }
  const r = await fetch(parsed);
  res.json({ status: r.status, ok: link.endsWith('.acme-media.com') });
}

module.exports = { preview };
