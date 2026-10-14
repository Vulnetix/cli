const pc = new RTCPeerConnection({
  iceServers: [
    { urls: 'stun:stun.example.org:3478' },
    { urls: 'turn:127.0.0.1:3478', username: 'dev', credential: 'dev' },
  ],
});
const allowed = peers.filter((p) => p.ip === '10.0.0.1');
if (host.indexOf('localhost') !== -1) {
  console.log('local dev');
}
module.exports = pc;
