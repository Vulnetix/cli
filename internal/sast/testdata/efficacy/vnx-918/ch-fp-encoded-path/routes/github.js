router.get("/gh/:user", async (req, res) => {
  const r = await fetch(`https://api.github.com/users/${encodeURIComponent(req.params.user)}`);
  const s = await axios.get(API_BASE + "/stats", { params: req.query });
  res.json(await r.json());
});
