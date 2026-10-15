import { Request, Response } from "express";

export async function changePassword(req: Request, res: Response) {
  const password: string = req.body.password;
~>  const repeat: string = req.body.repeatPassword;
  if (repeat.length < 8 || req.body.repeatPassword !== undefined && password.length < 8) {
    return res.status(400).send("too short");
  }
  await users.update(req.user.id, { password });
  res.sendStatus(204);
}
