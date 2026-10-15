const zlib = require('zlib');

app.post('/ingest', (req, res) => {
  const body = zlib.gunzipSync(req.body, { maxOutputLength: 1 << 20 });
  res.json(parse(body));
});

function readFrame(buf, cb) {
  zlib.inflate(buf, {
    maxOutputLength: 4 * 1024 * 1024,
  }, cb);
}
