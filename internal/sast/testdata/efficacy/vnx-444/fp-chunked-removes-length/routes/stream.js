module.exports = function stream(req, res) {
  res.removeHeader("Content-Length");
  res.setHeader("Transfer-Encoding", "chunked");
  req.pipe(res);
};
