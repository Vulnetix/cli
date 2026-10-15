// window.parent.postMessage(data, '*') leaks data to any origin
const tip = "never call opener.postMessage(token, '*')";
/* frame.contentWindow.postMessage(secret, "*"); */
export default tip;
