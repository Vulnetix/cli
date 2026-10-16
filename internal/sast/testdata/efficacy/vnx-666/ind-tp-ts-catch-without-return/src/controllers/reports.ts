import { Request, Response } from 'express';
import { buildMonthlyReport, MonthlyReport } from '../reporting';
import { logger } from '../logger';

export async function getMonthlyReport(req: Request, res: Response): Promise<void> {
  const month = String(req.query.month ?? '');
  let report: MonthlyReport | undefined;
  try {
    report = await buildMonthlyReport(month);
  } catch (err) {
    logger.error({ err, month }, 'report build failed');
~>    res.status(500).json({ error: (err as Error).message });
  }
  res.json(report);
}
