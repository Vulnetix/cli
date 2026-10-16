export async function signup(req: Request, res: Response) {
~>  const { email, password, confirmPassword } = req.body;
  const hash = await argon2.hash(password);
  await repo.create(email, hash);
  res.status(201).end();
}
