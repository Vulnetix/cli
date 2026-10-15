import { Router } from 'express';

export const reports = Router();

reports.get('/reports/all', async (req, res) => {
~>  if (req.query.isAdmin == 'true') {
    res.json(await db.allReports());
    return;
  }
  res.json(await db.reportsFor(req.user.id));
});
