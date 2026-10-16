import { Request, Response } from 'express';
import { buildReport } from './builder';

export async function monthly(req: Request, res: Response) {
  let report;
  try {
    report = await buildReport(req.query.month as string);
  } catch (err: any) {
~>    res.status(500).json({ error: err.message });
  }
  report.generatedAt = Date.now();
  res.json(report);
}
