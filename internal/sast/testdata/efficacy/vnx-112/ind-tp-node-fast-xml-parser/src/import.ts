import { XMLParser } from 'fast-xml-parser';
import type { Request, Response } from 'express';

const parser = new XMLParser({ ignoreAttributes: false });

export async function importCatalog(req: Request, res: Response) {
  const xml = req.body as string;
~>  const catalog = parser.parse(xml);
  for (const product of catalog.catalog.product) {
    await saveProduct(product['@_sku'], product.price);
  }
  res.sendStatus(202);
}
