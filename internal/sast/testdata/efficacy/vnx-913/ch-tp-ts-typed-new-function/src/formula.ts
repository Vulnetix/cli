import { Request, Response } from "express";

export function computeFormula(req: Request, res: Response) {
  const expr: string = req.query.expr as string;
~>  const fn = new Function("x", `return (${expr});`);
  res.send(String(fn(Number(req.query.x))));
}
