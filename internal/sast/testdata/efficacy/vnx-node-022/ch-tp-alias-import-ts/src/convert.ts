import { exec as run } from 'shelljs';
import { Request, Response } from 'express';

export function convert(req: Request, res: Response) {
  const name: string = req.params.file;
~>  run(
    'convert uploads/' + name + ' out.png',
    { silent: true }
  );
  res.sendStatus(204);
}
