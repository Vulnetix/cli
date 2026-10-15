const pc = new RTCPeerConnection({
  iceServers: [
    { urls: 'stun:stun.example.org:3478' },
    { urls: 'turn:turn.example.org:3478', username: 'u', credential: token },
  ],
});
const isLocal = ip === '127.0.0.1';
const peers = candidates.filter((c) => c.address !== '10.0.0.1');
