import express from 'express';
import routes from './routes.js';

~>const app = express();
app.use(express.json());
app.use('/api', routes);

app.use((req, res, next) => {
  res.status(404).json({ error: 'not found' });
});

export default app;
