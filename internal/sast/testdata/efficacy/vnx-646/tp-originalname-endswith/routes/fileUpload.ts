import { Request, Response, NextFunction } from 'express';

export function handleZip({ file }: Request, res: Response, next: NextFunction) {
~>  if (!(file?.originalname?.toLowerCase().endsWith('.zip') ?? false)) {
    return next();
  }
  unzip(file.buffer);
}

export function handleYaml(req: Request, res: Response, next: NextFunction) {
  const upload = req.files.doc;
~>  if (upload.name.endsWith('.yml') || upload.name.endsWith('.yaml')) {
    parseYaml(upload.data);
  }
  next();
}
