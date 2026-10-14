const formData = require("form-data");
const Mailgun = require("mailgun.js");

const mailgun = new Mailgun(formData);
const mg = mailgun.client({
  username: "api",
~>  key: "key-@@sample:[0-9a-z]{32}@@",
});
