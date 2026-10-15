const ALLOWED = new Set(['viewer', 'editor']);

async function acceptInvite(req, res) {
  const requested = req.body.role;
  if (!ALLOWED.has(requested)) {
    return res.status(400).json({ error: 'bad role' });
  }
  const user = await User.findById(req.user.id);
  user.role = requested;
  await user.save();
  res.sendStatus(204);
}

module.exports = { acceptInvite };
