import express, { Request, Response } from 'express';

const app = express();
app.use(express.json());
app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));
app.post('/items', (req: Request, res: Response) => res.status(201).json(req.body));
export default app;
