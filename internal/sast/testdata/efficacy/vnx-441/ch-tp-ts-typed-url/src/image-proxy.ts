import axios from "axios";
import { Request, Response } from "express";

export async function imageProxy(req: Request, res: Response): Promise<void> {
  const imageUrl: string = req.query.src as string;
~>  const upstream = await axios.get(imageUrl, {
    responseType: "arraybuffer",
  });
  res.type(upstream.headers["content-type"]);
  res.send(upstream.data);
}
