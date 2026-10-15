const zlib = require('zlib');

module.exports = function hook(req, res) {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const json = zlib.gunzipSync(body, {
      maxOutputLength: 1024 * 1024,
    }).toString('utf8');
    res.end(JSON.parse(json).id);
  });
};
