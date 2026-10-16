async function load(req, res) {
  const target = req.body.url;
  if (!target.startsWith('https://')) {
    return res.status(400).send('https only');
  }
  const referer = req.get('referer') || '';
  if (referer.includes('portal.example.com')) {
    res.set('x-from-portal', '1');
  }
  // if (target.includes('example.com')) fetch(target)
  const apiUrl = `${process.env.API_BASE}/v1/items`;
  const items = await fetch(apiUrl);
  return res.json(await items.json());
}
