import * as YAML from 'js-yaml';
import { Request, Response } from 'express';

export function importDoc(req: Request, res: Response) {
  const body: string = req.body as string;
~>  const doc = YAML.load(body, { schema: YAML.DEFAULT_FULL_SCHEMA });
  res.json(doc);
}
