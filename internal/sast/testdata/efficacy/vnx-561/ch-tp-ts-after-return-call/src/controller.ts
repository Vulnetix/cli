export async function update(req: Request, res: Response): Promise<Response> {
  const item = await repo.save(req.body);
  return res.json(item);
~>  metrics.increment('items.updated');
}
