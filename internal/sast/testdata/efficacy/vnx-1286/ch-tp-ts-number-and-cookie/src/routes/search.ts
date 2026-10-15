import { Router, Request, Response } from "express";

const router = Router();

router.get("/search", async (req: Request, res: Response) => {
~>  const limit = Number(req.query.limit);
  const items = await db.items.find().limit(limit);
  res.json(items);
});

router.get("/prefs", (req: Request, res: Response) => {
~>  const prefs = JSON.parse(req.cookies.prefs);
  res.json(prefs);
});

export default router;
