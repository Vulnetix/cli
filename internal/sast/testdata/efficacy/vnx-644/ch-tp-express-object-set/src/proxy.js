app.get("/whoami", (req, res) => {
~>  res.set({ "X-Forwarded-User": req.headers["x-user"], "Cache-Control": "no-store" });
  res.json({ ok: true });
});
