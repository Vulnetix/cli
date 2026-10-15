import express, { Request, Response } from "express";
import * as fs from "fs";

const router = express.Router();

router.get("/version", (_req: Request, res: Response) => {
~>  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
  res.json({ version: pkg.version });
});

export default router;
