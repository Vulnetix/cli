module.exports = function download(req, res) {
  const data = Buffer.from(JSON.stringify(req.user.export()));
  res.setHeader("Content-Length", data.length);
~>  res.setHeader("Transfer-Encoding", "chunked");
  res.end(data);
};
