'use strict';

const express = require('express');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(helmet.frameguard({ action: 'deny' }));
app.use(helmet.frameguard({ action: 'sameorigin' }));

const settings = { frameguardEnabled: false, showFrame: false };

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self' https://*.example.com");
  next();
});

app.use(helmet.contentSecurityPolicy({
  directives: {
    frameAncestors: ["'self'", 'https://admin.example.com'],
    imgSrc: ['*'],
  },
}));

// helmet({ frameguard: false }) was removed after the pentest.
module.exports = { app, settings };
