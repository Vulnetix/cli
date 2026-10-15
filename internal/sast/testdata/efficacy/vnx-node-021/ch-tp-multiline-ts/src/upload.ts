import * as libxmljs from 'libxmljs2';
import { Request, Response } from 'express';

export function upload(req: Request, res: Response) {
  const xml = req.file!.buffer.toString('utf8');
  const doc = libxmljs.parseXml(xml, {
    noblanks: true,
~>    noent : true,
    nocdata: true,
  });
  res.send(doc.root()!.name());
}
