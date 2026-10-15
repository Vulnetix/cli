import express, { Express, Request, Response } from 'express';

~>const app: Express = express();
const port = process.env.PORT || 8080;

app.get('/', (req: Request, res: Response) => {
  res.send(JSON.parse(req.query.payload as string));
});

app.listen(port, () => console.log(`listening on ${port}`));
