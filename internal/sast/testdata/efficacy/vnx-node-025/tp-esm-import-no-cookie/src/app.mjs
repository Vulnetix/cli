import express from 'express';
import expressSession from 'express-session';

const app = express();
~>app.use(expressSession({ secret: process.env.SECRET, resave: false, saveUninitialized: false }));
app.listen(8080);
