export const api = axios.create({
  baseURL: "https://api.acme.invalid",
  headers: {
~>    Authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJpc3MiOiJodHRwczovL2F1dGguYWNtZS5pbnZhbGlkIiwic3ViIjoiY2ktZGVwbG95ZXIiLCJzY29wZSI6ImRlcGxveTpwcm9kIiwiZXhwIjo0MTAyNDQ0ODAwfQ.@@sample:[A-Za-z0-9_\-]{342}@@',
  },
});
