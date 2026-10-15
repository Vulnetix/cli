import { Request, Response } from "express";
import * as bcrypt from "bcrypt";
import { Users } from "../models";

export async function changePassword(req: Request, res: Response) {
  const me = await Users.findByPk(req.session.uid);
  if (!me) {
    return res.status(404).send("User not found");
  }
  if (!(await bcrypt.compare(req.body.current, me.hash))) {
    return res.status(401).send("Current password is not correct");
  }
  await me.update({ hash: await bcrypt.hash(req.body.next, 12) });
  res.sendStatus(204);
}
