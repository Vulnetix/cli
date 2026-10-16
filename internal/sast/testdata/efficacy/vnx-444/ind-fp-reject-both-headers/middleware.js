module.exports = function rejectAmbiguousFraming(req, res, next) {
  const te = req.headers['transfer-encoding'];
  const cl = req.headers['content-length'];
  if (te !== undefined && cl !== undefined) {
    res.statusCode = 400;
    return res.end('Both Transfer-Encoding and Content-Length present');
  }
  next();
};
