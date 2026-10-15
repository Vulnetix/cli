import express from 'express';
import csurf from 'csurf';

const app = express();
app.use(csurf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] }));
const opts = { csrf: true, checkOrigin: true };
const isCsrfEnabled = config.csrf !== false;
export default app;
