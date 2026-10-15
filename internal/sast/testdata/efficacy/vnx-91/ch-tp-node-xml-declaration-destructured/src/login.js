const express = require("express");
const xml2js = require("xml2js");
const app = express();

app.post("/login", async (req, res) => {
  const { username } = req.body;
~>  const xml = `<?xml version="1.0"?><login><user>${username}</user></login>`;
  const parsed = await @@sample:x[m]l2[j]s[.][p]ar[s]eS[t]ri[n]gP[r]om[i]se@@(xml);
  res.json(parsed);
});
