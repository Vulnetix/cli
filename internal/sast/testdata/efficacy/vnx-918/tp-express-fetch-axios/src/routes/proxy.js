const axios = require('axios');

router.get('/proxy', async (req, res) => {
~>  const r = await axios.get(req.query.url);
  const { target } = req.body;
~>  const page = await fetch(target);
  res.send(r.data + (await page.text()));
});
