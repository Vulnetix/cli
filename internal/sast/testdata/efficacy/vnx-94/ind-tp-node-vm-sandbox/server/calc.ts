import vm from 'node:vm';
import type { Request, Response } from 'express';

export function calculate(req: Request, res: Response) {
  const sandbox = { Math, result: 0 };
  vm.createContext(sandbox);
~>  vm.runInContext('result = ' + req.query.expr, sandbox, { timeout: 50 });
  res.json({ result: sandbox.result });
}

export function preview(req: Request, res: Response) {
  const source = String(req.body.snippet);
~>  const script = new vm.Script(source);
  res.json({ ok: true, out: script.runInNewContext({}) });
}
