const ALLOWED_HOSTS = new Set(['api.partner.example', 'cdn.partner.example']);

module.exports.relay = async (req, res) => {
  const url = new URL(req.query.u);
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    return res.sendStatus(400);
  }
  const upstream = await fetch(url, { redirect: 'error' });
  res.status(upstream.status).send(await upstream.text());
};
