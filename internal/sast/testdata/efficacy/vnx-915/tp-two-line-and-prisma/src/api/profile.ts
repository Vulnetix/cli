import { prisma } from '../db';

export async function update(req, res) {
  const changes = req.body;
~>  await prisma.user.update({ where: { id: req.user.id }, data: changes });
~>  await prisma.user.create({ data: req.body });
  res.sendStatus(204);
}
