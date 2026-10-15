async function preview(req, res) {
  const target = req.query.url;
  if (!target.startsWith('https://cdn.acme-media.com/')) {
    return res.status(400).send('host not allowed');
  }
  const upstream = await fetch(target);
  res.send(await upstream.text());
}

function isImage(name) {
  return name.endsWith('.png') || name.includes('thumbnail.jpg');
}

async function load(file) {
  if (file.endsWith('report.json')) {
    return fetch(file);
  }
}

module.exports = { preview, isImage, load };
