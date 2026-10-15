export class OrdersController {
  async update(req: Request, res: Response) {
    const order = await this.repo.findOneBy({ id: req.params.id });
~>    this.repo.merge(order, req.body);
    await this.repo.save(order);
    res.json(order);
  }
}
