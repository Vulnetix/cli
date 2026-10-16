import { Request, Response } from 'express';

// String methods that only exist on strings: an array or object from
// ?q[]=a or a JSON body throws TypeError on each of them.
export function report(req: Request, res: Response) {
~>  const at = req.query.q.search(/[<>]/);
~>  const banner = req.body.banner.repeat(3);
~>  const label = req.body.prefix.concat(':');
  res.json({ at, banner, label });
}
