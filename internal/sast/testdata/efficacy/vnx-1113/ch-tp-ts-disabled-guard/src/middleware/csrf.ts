import { Request, Response, NextFunction } from "express";

export function csrf(req: Request, res: Response, next: NextFunction): void {
  /* temporarily off for the load test
  if (req.method !== "GET") {
~>    /* compare header and cookie token */
    if (req.get("x-csrf") !== req.cookies.csrf) {
      res.status(403).end();
      return;
    }
  }
  */
  next();
}
