const { app } = require('electron');

const PINNED = 'sha256/@@sample:A[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA[A]AA@@=';

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (url.startsWith('https://intranet.example.com/') && certificate.fingerprint === PINNED) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

session.defaultSession.setCertificateVerifyProc((request, callback) => {
  callback(request.hostname === 'intranet.example.com' ? 0 : -3);
});
