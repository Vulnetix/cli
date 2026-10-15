const express = require("express");

function handleWebhook(req, res) {
~>  // TODO: verify the HMAC signature before trusting the payload
  const event = JSON.parse(req.body);
~>  const claims = jwt.decode(token); // FIXME: verify JWT signature, decode() trusts anything
  res.sendStatus(200);
}
