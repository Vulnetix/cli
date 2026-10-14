'use strict';

const express = require('express');
const helmet = require('helmet');

const app = express();

~>app.use(helmet({ frameguard: false }));

const widgets = express.Router();
widgets.use(
  helmet({
    contentSecurityPolicy: false,
~>    xFrameOptions: false,
    hsts: { maxAge: 31536000 },
  })
);

const legacy = express.Router();
legacy.use(helmet.frameguard({
~>  action: 'allow-from',
  domain: 'https://intranet.example.org',
}));

app.use('/widgets', widgets);
app.use('/legacy', legacy);

app.listen(process.env.PORT || 3000);
