import { Request, Response } from "express";

export async function removePost(req: Request, res: Response) {
~>  await prisma.post.delete({ where: { id: Number(req.params.id) } });
  res.status(204).end();
}

export async function editPost(req: Request, res: Response) {
~>  const post = await prisma.post.update({ where: { id: req.params.postId }, data: req.body });
  res.json(post);
}
