export async function provision(req, res) {
  const user = await repo.findOneByOrFail({ id: req.user.id });
  user['role'] = 'member';
  user.roles.push('viewer');
  user.tags.push(req.body.tag);
  await repo.save(user);
  res.json(user);
}
