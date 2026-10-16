window.opener.postMessage({ type: 'oauth', token }, 'https://app.example.com');
frame.contentWindow.postMessage(session, window.location.origin);
worker.postMessage({ job: 1 });
port.postMessage(data);
// window.opener.postMessage(secret, '*');
const doc = "postMessage(x, '*')";
