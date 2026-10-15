export async function search(req: any, res: any) {
~>  const users = await db.collection('users').find({
    $or: [{ email: req.body.login }, { username: req.body.login }],
  }).toArray();
  res.json(users);
}
