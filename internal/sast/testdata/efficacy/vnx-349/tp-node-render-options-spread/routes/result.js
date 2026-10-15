router.post("/result", (req, res) => {
  const theme = { brand: config.brand, logo: config.logo };
  res.render("result", {
~>    ...req.body,
    ...theme,
  });
});

router.get("/inline", (req, res) => {
~>  res.render("inline", { ...req.query, title: "Inline" });
});

router.post("/echo", (req, res) => {
  res.json({ ...req.body, ok: true });
});
