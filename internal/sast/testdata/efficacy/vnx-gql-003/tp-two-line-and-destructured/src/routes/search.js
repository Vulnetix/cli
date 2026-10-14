const express = require('express');
const { request } = require('graphql-request');

const router = express.Router();
const ENDPOINT = process.env.GRAPHQL_URL;

router.post('/search', async (req, res) => {
  const term = req.body.term;
~>  const doc = `query Search { products(filter: "${term}") { id title } }`;
  res.json(await request(ENDPOINT, doc));
});

router.post('/profile', async (req, res) => {
  const { fields, userId: uid } = req.body;
~>  const doc = `query Profile { user(id: "${uid}") { ${fields} } }`;
  res.json(await request(ENDPOINT, doc));
});

module.exports = router;
