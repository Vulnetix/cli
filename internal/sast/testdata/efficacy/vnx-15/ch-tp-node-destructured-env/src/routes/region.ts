import { Router, Request, Response } from "express";

const router = Router();

router.post("/region", (req: Request, res: Response) => {
  const { region } = req.body;
~>  process.env.AWS_REGION = region;
  res.sendStatus(204);
});

router.post("/flag", (req: Request, res: Response) => {
~>  process.env[req.query.name as string] = String(req.query.value);
  res.sendStatus(204);
});

export default router;
