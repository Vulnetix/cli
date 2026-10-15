function startPolling(jobId, handler) {
~>  setInterval(`refreshJob('${jobId}', ${handler})`, 2000);
}

function later(name) {
~>  window.setTimeout("notify('" + name + "')", 500);
}
