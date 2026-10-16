const http = require('http');
const axios = require('axios');
const needle = require('needle');
const got = require('got');

exports.health = (req, res) => {
~>  http.get(`http://${req.query.host}:8080/healthz`, (up) => {
    res.sendStatus(up.statusCode === 200 ? 204 : 502);
  });
};

exports.feed = (req, res) => {
  const target = req.query.feed + '/quote?s=' + req.query.symbol;
~>  needle.get(target, (err) => {
    res.sendStatus(err ? 502 : 204);
  });
};

exports.tenant = async (req, res) => {
~>  await axios.get(`https://${req.query.tenant}.example.com/api/warm`);
  res.sendStatus(204);
};

exports.check = async (req, res) => {
~>  const reply = await got(req.query.target);
  res.json({ ok: reply.statusCode < 400 });
};
