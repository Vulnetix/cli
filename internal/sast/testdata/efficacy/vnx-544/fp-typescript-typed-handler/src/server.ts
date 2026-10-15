import express, { NextFunction, Request, Response } from 'express';

const app = express();
app.get('/', (req: Request, res: Response) => res.send('ok'));
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  res.status(500).send('error');
});
app.listen(8080);
