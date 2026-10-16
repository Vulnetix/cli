function handle(req, res) {
~>  // HACK: skipping signature verification, vulnerable to token forgery
  const payload = JSON.parse(req.body);
  res.json(payload);
}
module.exports = handle;
