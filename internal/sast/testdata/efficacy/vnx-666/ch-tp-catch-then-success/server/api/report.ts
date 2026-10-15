import { Request, Response } from 'express';

export async function getReport(req: Request, res: Response) {
  let report;
  try {
    report = await buildReport(req.query.month as string);
  } catch (err) {
~>    res.status(500).json({ error: (err as Error).message });
  }
  res.json(report);
}
