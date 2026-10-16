const express = require('express');
const axios = require('axios');

const app = express();
const WEATHER_URL = 'https://api.weather.example.com/v1/forecast';

app.get('/weather', async (req, res) => {
  const { data } = await axios.get(WEATHER_URL, {
    params: { city: req.query.city, units: 'metric' },
    timeout: 4000,
  });
  res.json(data);
});

module.exports = app;
