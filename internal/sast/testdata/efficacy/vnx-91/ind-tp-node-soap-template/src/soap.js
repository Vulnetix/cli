'use strict';

const axios = require('axios');
const express = require('express');

const app = express();
app.use(express.json());

app.post('/customers', async (req, res) => {
~>  const body = `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateCustomer><name>${req.body.name}</name></CreateCustomer></soap:Body></soap:Envelope>`;
  const r = await axios.post('https://crm.internal/soap', body, {
    headers: { 'Content-Type': 'text/xml; charset=utf-8' },
  });
  res.status(r.status).end();
});

module.exports = app;
