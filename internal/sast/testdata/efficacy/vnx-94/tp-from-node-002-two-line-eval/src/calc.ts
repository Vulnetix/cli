import { Request, Response } from "express";

export function calculate(req: Request, res: Response) {
  const expression = String(req.query.expr);
~>  const result = eval(expression);
  res.send({ result });
}
