import { Request, Response } from "express";

export function setPort(req: Request, res: Response): void {
  const raw = req.params.port;
~>  const port: number = parseInt(raw);
  res.send({ port });
}

export function cliLevel(): number {
  const level = process.argv[2];
~>  return parseInt(level);
}

export function fromUrl(): number {
  const id = new URLSearchParams(window.location.search).get("id");
~>  return parseInt(id);
}
