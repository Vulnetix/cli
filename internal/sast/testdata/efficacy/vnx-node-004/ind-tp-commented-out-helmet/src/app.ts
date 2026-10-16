import express from 'express';
// import helmet from 'helmet';

~>export const app = express();
// app.use(helmet());
/*
app.use(helmet.frameguard({ action: 'deny' }));
*/
app.get('/', (_req, res) => res.send('hi'));
