const axios = require("axios");

module.exports = function register(app) {
  app.get("/check", async (req, res) => {
    const target = req.query.url;
    const r = await axios.head(target, { timeout: 2000 });
    res.json({ reachable: r.status < 400 });
  });
};
