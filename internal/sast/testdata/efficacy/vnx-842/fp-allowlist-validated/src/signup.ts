const PUBLIC_ROLES = ['reader', 'writer'];

export async function signUp(req: Request, res: Response) {
  const role = String(req.body.role);
  if (!PUBLIC_ROLES.includes(role)) {
    return res.status(400).end();
  }
  const user = await prisma.user.create({ data: { email: req.body.email, role } });
  user.role = role;
  return res.json(user);
}
