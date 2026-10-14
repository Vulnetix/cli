const axios = require('axios');
const config = require('./config');

const API_BASE = 'https://api.example.com';

async function profile(req, res) {
  const user = await fetch(`${API_BASE}/users/me`, {
    headers: { authorization: req.headers.authorization },
  });
  res.json(await user.json());
}

async function orders(req, res) {
  const page = Number(req.query.page) || 1;
  const { data } = await axios.get(config.ordersUrl, { params: { page, q: req.query.q } });
  res.json(data);
}

async function search(req, res) {
  const { data } = await axios.post(`${API_BASE}/search`, { term: req.body.term });
  res.json(data);
}

module.exports = { profile, orders, search };

async function item(req, res) {
  const r = await fetch(API_BASE + '/items/' + req.params.id);
  const s = await axios.get(`${config.apiUrl}/users/${req.query.user}`);
  const t = await fetch(`https://api.example.com/v1/orders/${req.params.order}`);
  res.json({ r: await r.json(), s: s.data, t: await t.json() });
}

module.exports.item = item;
