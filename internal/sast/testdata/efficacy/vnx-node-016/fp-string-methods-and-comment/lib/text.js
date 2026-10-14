// new RegExp(req.query.pattern) lets a client pick a catastrophic pattern.
function edit(req, res) {
  const out = req.body.text.replace(req.query.find, '');
  const parts = req.body.text.split(req.query.sep);
  const has = req.body.text.includes(req.query.q);
  const hint = 'avoid new RegExp(req.query.x)';
  res.json({ out, parts, has, hint });
}

async function hits(req, res) {
  const result = await index.search(req.query.q, { hitsPerPage: 10 });
  res.json(result);
}

module.exports = { edit, hits };
