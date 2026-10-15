function readTicket(req, res) {
~>  const [userId, role, expires] = Buffer.from(req.query.t, "hex").toString().split(":");
  if (Number(expires) < Date.now()) return res.sendStatus(410);
  res.json({ userId, role });
}

module.exports = { readTicket };
