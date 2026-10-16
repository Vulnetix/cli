exports.forgot = async (req, res) => {
~>  const resetToken = Math.random().toString(36).slice(2);
  await save(req.body.email, resetToken);
  res.sendStatus(204);
};
