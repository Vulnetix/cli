import express from 'express';
import helmet from 'helmet';

const app = express();
app.use(
  helmet.contentSecurityPolicy({
    directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] },
  }),
);
app.use(express.static('dist'));
app.listen(3000);
