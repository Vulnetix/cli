import vm from 'vm';
import { Request, Response } from 'express';

export function compileRule(req: Request, res: Response) {
  const body: string = req.body.rule;
~>  const fn = new Function('item', body);
  res.json({ ok: fn({}) });
}

export function sandbox(req: Request, res: Response) {
~>  const value = vm.runInNewContext(req.body.code, { Math });
  res.json({ value });
}

export function later(req: Request) {
~>  setTimeout("refresh('" + req.query.panel + "')", 500);
~>  const script = new vm.Script(
    req.body.source
  );
  return script;
}
