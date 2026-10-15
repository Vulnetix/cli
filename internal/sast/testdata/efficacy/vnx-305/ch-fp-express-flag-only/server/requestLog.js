function tagRequest(req, res, next) {
  if (req.headers.authorization) {
    res.locals.hasAuthHeader = true;
  }
  next();
}

module.exports = tagRequest;
