async function cancel(req, res) {
  await authorizeOwner(req.user, req.params.id);
~>  await authorizeOwner(req.user, req.params.id);
  res.sendStatus(204);
}
module.exports = { cancel };
