import { Request, Response } from "express";

const UPSTREAM = "https://search.internal.example.com";

export async function search(req: Request, res: Response) {
  const q = encodeURIComponent(String(req.query.q ?? ""));
  const r = await fetch(`${UPSTREAM}/v1/search?q=${q}`);
  res.json(await r.json());
}
