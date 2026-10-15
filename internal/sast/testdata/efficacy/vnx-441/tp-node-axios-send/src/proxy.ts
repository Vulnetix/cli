import axios from "axios";
import { Request, Response } from "express";

export async function relay(req: Request, res: Response) {
  const target = req.body.endpoint as string;
~>  const upstream = await axios.get(
    target,
    { timeout: 3000 },
  );
  res.status(upstream.status).send(upstream.data);
}

export async function relayFetch(req: Request, res: Response) {
~>  const r = await fetch(`${req.query.base}/v1/items`);
  res.send(await r.text());
}
