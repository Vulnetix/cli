module.exports = (req, res) => {
~>  res.setHeader("Access-Control-Allow-Origin", "*");
  res.end(JSON.stringify({ ok: true }));
};
