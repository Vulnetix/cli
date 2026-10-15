import { Router, Request, Response } from 'express';
import * as vm from 'node:vm';

const router = Router();

router.post('/formula', (req: Request, res: Response) => {
  const formula: string = req.body.formula;
  const sandbox = { price: 10, qty: 3 };
~>  const value = vm.runInNewContext(formula, sandbox, { timeout: 50 });
  res.json({ value });
});

router.get('/score', (req: Request, res: Response) => {
~>  const scorer = new Function('row',
    `return ${req.query.expr};`);
  res.json(rows.map((r) => scorer(r)));
});

export default router;
