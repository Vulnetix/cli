import express, { Request, Response } from 'express';
import cors from 'cors';
import { listProducts } from './services/products';

~>const app = express();

app.use(cors());
app.use(express.json());

app.get('/products', async (req: Request, res: Response) => {
  res.json(await listProducts(req.query));
});

export default app;
