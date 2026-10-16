// window.addEventListener('message', h) without origin check is bad
const t = "target.postMessage(x, '*')";
export default t;
