module.exports = function iceServers() {
  return [{ urls: 'turn:rooms.example.org:3478', username: 'u', credential: 'c' }];
};
