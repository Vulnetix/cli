import express, { NextFunction, Request, Response } from 'express';
import { HttpError } from './errors';

const app = express();
app.get('/health', (_req: Request, res: Response) => res.send('ok'));

app.use(
  (
    error: HttpError,
    request: Request,
    response: Response,
    next: NextFunction,
  ) => {
    response.status(error.status ?? 500).json({ message: 'request failed' });
  },
);

app.listen(3000);
