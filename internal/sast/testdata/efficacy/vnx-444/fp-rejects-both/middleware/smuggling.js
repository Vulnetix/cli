module.exports = function rejectAmbiguous(req, res, next) {
  const te = req.headers["transfer-encoding"];
  const cl = req.headers["content-length"];
  if (te && cl) {
    res.statusCode = 400;
    return res.end("ambiguous framing");
  }
  return next();
};
