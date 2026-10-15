import express from 'express';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';

const app = express();
app.use(cookieParser());
~>app.use(csurf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'] }));

export default app;
