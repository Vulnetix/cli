const https = require("https");

router.get("/stock", (req, res) => {
  const r = https.request({
    host: "inventory.internal.example.com",
    path: `/v1/stock/${encodeURIComponent(req.query.sku)}`,
    method: "GET",
  });
  r.end();
});
