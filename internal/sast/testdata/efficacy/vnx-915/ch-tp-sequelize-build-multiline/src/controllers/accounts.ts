export async function register(req: Request, res: Response) {
  const input = req.body;
~>  const account = Account.build(input);
  await account.save();
  res.status(201).json(account);
}
