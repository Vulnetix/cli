const express = require('express');
const xml2js = require('xml2js');
const Joi = require('joi');
const router = express.Router();

const feedSchema = Joi.object({ feed: Joi.object().required() });

router.post('/feed', async (req, res) => {
  const result = await @@sample:x[m]l2[j]s[.][p]ar[s]eS[t]ri[n]gP[r]om[i]se@@(req.body);
  const { error } = feedSchema.validate(result);
  if (error) return res.sendStatus(400);
  res.json(result);
});

module.exports = router;
