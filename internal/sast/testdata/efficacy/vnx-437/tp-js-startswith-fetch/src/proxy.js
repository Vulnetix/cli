const express = require('express');
const app = express();

app.get('/preview', async (req, res) => {
  const target = req.query.url;
  if (!target.startsWith('https://cdn.acme-media.com')) {
    return res.status(400).send('host not allowed');
  }
~>  const upstream = await fetch(target, { redirect: 'manual' });
  res.type(upstream.headers.get('content-type'));
  res.send(Buffer.from(await upstream.arrayBuffer()));
});

app.get('/thumb', async (req, res) => {
  const src = String(req.query.src);
  if (src.startsWith("https://img.acme-media.com")) {
~>    const r = await axios.get(src,
      { responseType: 'arraybuffer' });
    return res.send(r.data);
  }
  res.sendStatus(404);
});
