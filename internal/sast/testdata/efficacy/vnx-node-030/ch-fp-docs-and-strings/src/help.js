// To debug locally you may set --allow-loopback-peers in turnserver.conf
const message = 'Never ship allowed-peer-ip=10.0.0.0 to production';
const nodeTurnDocs = "new Turn({}) is from the node-turn package";
module.exports = { message, nodeTurnDocs };
