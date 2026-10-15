const zlib = require('zlib');
const { inflateSync } = require('zlib');

app.post('/ingest', (req, res) => {
~>  const body = zlib.gunzipSync(req.body);
  res.json(parse(body));
});

function readFrame(buf, cb) {
~>  zlib.inflate(buf, (err, out) => {
    if (err) return cb(err);
    cb(null, out);
  });
}

function readBrotli(buf) {
~>  return zlib.brotliDecompressSync(
    buf
  );
}

function readRaw(buf) {
~>  return inflateSync(buf);
}
