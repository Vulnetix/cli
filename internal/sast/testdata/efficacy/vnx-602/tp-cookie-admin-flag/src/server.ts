import express, { Request, Response } from 'express';

const app = express();

app.get('/admin', (req: Request, res: Response) => {
  const role = req.cookies.role;
~>  if (role !== 'admin') {
    return res.status(403).send('forbidden');
  }
  res.send(renderAdmin());
});

app.get('/billing', (req: Request, res: Response) => {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  const allowed = req.cookies['is_admin'] === 'true';
  res.send(allowed ? renderBilling() : 'no');
});
