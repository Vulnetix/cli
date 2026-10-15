import type { Request, Response } from 'express';

export async function weather(req: Request, res: Response): Promise<void> {
  const report = await fetchReport(String(req.query.city));
  res.type('application/javascript');
~>  res.send(`${req.query.jsoncallback}(${JSON.stringify(report)});`);
}
