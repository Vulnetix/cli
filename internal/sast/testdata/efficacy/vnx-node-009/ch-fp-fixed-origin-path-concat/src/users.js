const axios = require('axios');

exports.user = async (req, res) => {
  const a = await fetch('https://api.example.com/users/' + encodeURIComponent(req.params.id));
  const b = await axios.get(`https://api.example.com/orders?user=${req.query.user}`);
  res.json({ a: await a.json(), b: b.data });
};
