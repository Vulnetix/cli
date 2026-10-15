const express = require('express');
const { DOMParser } = require('@xmldom/xmldom');
const libxmljs = require('libxmljs2');

const app = express();
app.use(express.text({ type: 'application/xml' }));

app.post('/ingest', (req, res) => {
~>  const doc = new DOMParser().parseFromString(req.body, 'text/xml');
  res.json({ nodes: doc.documentElement.childNodes.length });
});

app.post('/legacy', (req, res) => {
  const xml = req.body.toString('utf8');
~>  const parsed = libxmljs.parseXml(xml, { noent: false });
  res.json({ root: parsed.root().name() });
});
