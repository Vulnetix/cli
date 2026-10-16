const axios = require("axios");

async function fetchManifest(url, username, password) {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const headers = { Authorization: `Basic ${auth}` };
  console.log("fetching manifest", url);
  const res = await axios.get(url, { headers });
  console.info("manifest status", res.status);
  return res.data;
}

module.exports = { fetchManifest };
