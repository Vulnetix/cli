const worker = new Worker('/compute.js');
worker.postMessage({ cmd: 'start' });
window.postMessage('tick', '*');
self.postMessage({ done: true }, '*');
postMessage('ready', '*');
const channel = new MessageChannel();
@@sample:c[h]an[n]el[.]po[r]t1[.]po[s]tM[e]ss[a]ge@@('hello');
const pricingWorker = new Worker('/pricing.js');
pricingWorker.postMessage({ sku: 1 });
function nextTick(callback, win) {
  win = win || window;
  var name = 'zero-timeout-' + Date.now();
  win.addEventListener('message', function (e) {
    if (e.data === name) callback();
  });
  win.postMessage(name, '*');
}
