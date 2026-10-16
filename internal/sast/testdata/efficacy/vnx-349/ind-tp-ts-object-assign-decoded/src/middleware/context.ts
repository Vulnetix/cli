import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

export function buildContext(req: Request, res: Response, next: NextFunction) {
  const token = (req.headers.authorization || "").replace(/^Bearer /, "");
  const decoded = jwt.verify(token, process.env.JWT_KEY as string) as Record<string, unknown>;
~>  const ctx = Object.assign(decoded, req.body);
  res.locals.ctx = ctx;
  next();
}
