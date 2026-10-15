import * as child from "child_process";
import type { Request, Response } from "express";

export function ping(req: Request, res: Response): void {
  const host = String(req.query.host);
~>  child.exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(err ? "down" : stdout);
  });
}
