const zlib = require('zlib');

function maybeCompress(req, res, payload) {
  res.setHeader('Content-Length', payload.length);
  if (/\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    res.removeHeader('Content-Length');
    res.setHeader('Content-Encoding', 'gzip');
    res.setHeader('Transfer-Encoding', 'chunked');
    const gz = zlib.createGzip();
    gz.pipe(res);
    gz.end(payload);
    return;
  }
  res.end(payload);
}

module.exports = { maybeCompress };
