const sgMail = require('@sendgrid/mail');

const key =
~>  '@@sample:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}@@';

sgMail.setApiKey(key);

async function notify(to, text) {
  await sgMail.send({ to, from: 'noreply@shop.example', subject: 'Alert', text });
}

module.exports = { notify };
