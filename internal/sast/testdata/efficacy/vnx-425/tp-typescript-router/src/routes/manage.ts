import { Router, Request, Response } from 'express';
import { reloadConfig, purgeCache } from '../services/config';

export const manageRouter = Router();

~>manageRouter.post('/manage/config/reload', reloadConfig);
~>manageRouter.delete(
  '/administrator/cache', (req: Request, res: Response) => {
    purgeCache();
    res.status(200).end();
  });
manageRouter.get('/health', (_req: Request, res: Response) => res.send('ok'));
