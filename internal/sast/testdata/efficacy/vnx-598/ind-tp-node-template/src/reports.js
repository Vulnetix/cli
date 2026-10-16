const axios = require('axios');

const BASE = process.env.REPORTS_URL || 'https://reports.example.com';

async function fetchReport(apiKey, reportId) {
~>  const url = `${BASE}/v2/reports/${reportId}?api_key=${apiKey}&format=json`;
  const { data } = await axios.get(url, { timeout: 10000 });
  return data;
}

module.exports = { fetchReport };
