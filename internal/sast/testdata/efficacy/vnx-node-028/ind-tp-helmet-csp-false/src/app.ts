import express from 'express';
import helmet from 'helmet';

const app = express();
app.set('view engine', 'ejs');
app.use(helmet({
~>  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.get('/', (req, res) => res.render('home'));
export default app;
