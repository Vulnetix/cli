const express = require('express');
const router = express.Router();

router.get('/admin/users/:id', requireAdmin, async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ id: user.id, email: user.email });
});

router.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  const n = await User.deleteOne({ _id: req.params.id });
  if (n.deletedCount === 0) return res.status(404).json({ error: 'user does not exist' });
  res.status(204).end();
});
