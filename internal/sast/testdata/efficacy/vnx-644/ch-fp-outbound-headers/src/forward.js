async function forward(req, res) {
  const headers = new Headers();
  headers.set("Authorization", req.headers.authorization);
  const upstream = await fetch(API_URL, { headers });
  res.status(upstream.status).send(await upstream.text());
}
