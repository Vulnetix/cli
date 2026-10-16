export function createPeer(): RTCPeerConnection {
  return new RTCPeerConnection({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'turn:turn.example.org:3478', username: 'u', credential: 'p' },
    ],
  });
}
export function isPrivate(ip: string) {
  return ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1';
}
