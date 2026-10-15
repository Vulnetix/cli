function respond(res, body, streaming) {
  if (streaming) {
    res.setHeader("Transfer-Encoding", "chunked");
    body.pipe(res);
    return;
  }
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.end(body);
}

module.exports = respond;
