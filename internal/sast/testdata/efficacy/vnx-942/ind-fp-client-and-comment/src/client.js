// server sends Access-Control-Allow-Origin: * on this endpoint
const h = { 'Access-Control-Allow-Origin': 'x' };
xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
const msg = "set Access-Control-Allow-Origin to * is unsafe";
