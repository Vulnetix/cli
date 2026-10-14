'use strict';
const axios = require('axios');
const https = require('https');

exports.register = async function register(req, res) {
  const { webhookUrl } = req.body;
~>  await axios.post(webhookUrl, { event: 'registered' });
  res.status(201).end();
};

exports.status = async function status(req, res) {
  const host = req.query.host;
  const target = 'https://' + host + ':8443/status';
~>  const reply = await fetch(target, { method: 'GET' });
  res.json(await reply.json());
};

exports.avatar = function avatar(req, res) {
  let imageUrl = req.body.imageUrl;
~>  https.get(imageUrl, (upstream) => upstream.pipe(res));
};
