export function check(req: Request, res: Response) {
  const original = req.file.originalname;
  const ext = path.extname(original);
~>  if (ext === '.svg') {
    return res.status(400).end();
  }
  res.sendStatus(200);
}
