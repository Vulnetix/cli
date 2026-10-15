exports.update = (req, res) => {
  /* old implementation
  const a = parseInt(req.body.a);
  */
  const preTax = parseInt(req.body.preTax);
  const roth = parseInt(req.body.roth);
  const { userId } = req.session;

  // validate both values before use
  const invalid = [isNaN(preTax), isNaN(roth), preTax < 0, roth < 0];
  if (invalid.some(Boolean)) return res.sendStatus(400);
  save(userId, preTax, roth);
};
