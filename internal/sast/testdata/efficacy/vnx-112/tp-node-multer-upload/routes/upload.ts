import { Request, Response } from 'express';
import { parseXmlString } from '../lib/xml';

export async function handleUpload({ file }: Request, res: Response) {
  if (file?.buffer == null) {
    return res.sendStatus(400);
  }
  const text = file.buffer.toString();
~>  const doc = await parseXmlString(text);
  res.json({ root: doc.root().name() });
}
