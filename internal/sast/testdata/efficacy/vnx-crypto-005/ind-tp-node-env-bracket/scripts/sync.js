#!/usr/bin/env node
~>process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

const fetch = require('node-fetch');

(async () => {
  const res = await fetch('https://staging.example.com/api/export');
  console.log(await res.text());
})();
