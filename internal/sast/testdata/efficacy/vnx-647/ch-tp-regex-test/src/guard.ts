import { NextFunction, Request, Response } from "express";

export function guard(req: Request, res: Response, next: NextFunction) {
~>  if (/^\/admin/.test(req.path) && !req.session.isAdmin) {
    res.status(403).end();
    return;
  }
  next();
}
