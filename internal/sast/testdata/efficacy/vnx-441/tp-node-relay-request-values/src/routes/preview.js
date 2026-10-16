const express = require('express');
const axios = require('axios');
const got = require('got');

const router = express.Router();

router.get('/preview', async (req, res) => {
~>  const page = await fetch(req.query.url);
  res.send(await page.text());
});

router.post('/import', async (req, res) => {
~>  const { data } = await axios.get(req.body.feedUrl, { timeout: 5000 });
  res.json(data);
});

router.get('/ping/:host', async (req, res) => {
~>  const r = await got(`http://${req.params.host}/health`);
  res.send(r.body);
});

router.post('/hook', async (req, res) => {
  await axios.post(req.body.callback, { ok: true });
  res.sendStatus(204);
});

module.exports = router;
