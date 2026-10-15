import { Request, Response } from "express";

export function download(req: Request, res: Response) {
~>  res.setHeader("Content-Disposition", `attachment; filename="${req.query.file}"`);
  res.sendFile(resolveFile(String(req.query.file)));
}
