const axios = require("axios");

const WEATHER_API = "https://api.weather.example/v2/forecast";

module.exports = async function forecast(req, res) {
  const city = encodeURIComponent(req.query.city || "");
  const upstream = await axios.get(WEATHER_API, { params: { city } });
  res.json(upstream.data);
};
