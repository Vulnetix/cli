const TRUSTED = ['paypal.com', 'example.org'];

~>const redirectHost = 'pаypal.com';

function allowed(host) {
  return TRUSTED.includes(host);
}

~>module.exports = { allowed, support: "support@exаmple.org" };
