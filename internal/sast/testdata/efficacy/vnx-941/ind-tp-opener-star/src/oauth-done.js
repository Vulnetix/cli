const token = readToken();
~>window.opener.postMessage({ type: 'oauth', token }, '*');
window.close();
