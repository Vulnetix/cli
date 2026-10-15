import { Request, Response } from "express";

export function dispatch(req: Request, res: Response) {
  const fn = req.body.method;
~>  const result = globalThis[fn](req.body.args);
  res.json({ result });
}

export function readGlobal(req: Request, res: Response) {
~>  res.json({ value: global[req.query.name as string] });
}
