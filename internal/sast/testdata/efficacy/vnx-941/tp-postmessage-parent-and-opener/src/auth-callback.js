const params = new URLSearchParams(location.hash.slice(1));
const token = params.get('access_token');

if (window.opener) {
~>  window.opener.postMessage({ type: 'oauth', token }, '*');
} else {
~>  parent.postMessage(JSON.stringify({ token: token }), "*");
}
~>window.top.postMessage({ height: document.body.scrollHeight }, '*');
