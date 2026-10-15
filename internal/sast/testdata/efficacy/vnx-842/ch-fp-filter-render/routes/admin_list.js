async function listUsers(req, res) {
  const role = req.query.role || 'all';
  const users = await User.find(role === 'all' ? {} : { role });
  res.render('users', { users, role });
}

module.exports = { listUsers };
