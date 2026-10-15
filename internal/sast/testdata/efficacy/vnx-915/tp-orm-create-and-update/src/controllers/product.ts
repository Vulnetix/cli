import { Product } from '../models';

export async function create(req, res) {
~>  const p = await Product.create(req.body);
~>  await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
~>  await Product.update(req.body, { where: { id: req.params.id } });
  res.json(p);
}
