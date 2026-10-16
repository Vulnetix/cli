import express, { NextFunction, Request, Response } from 'express';

const app = express();

app.get('/', (_req: Request, res: Response) => {
  res.send('hello');
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  res.status(500).json({ message: 'Something went wrong' });
});

export default app;
