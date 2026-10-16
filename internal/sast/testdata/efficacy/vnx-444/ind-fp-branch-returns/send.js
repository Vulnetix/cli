function sendBody(res, body, stream) {
  if (typeof body === 'string' || Buffer.isBuffer(body)) {
    res.setHeader('Content-Length', Buffer.byteLength(body));
    return res.end(body);
  }
  res.setHeader('Transfer-Encoding', 'chunked');
  stream.pipe(res);
}

module.exports = { sendBody };
