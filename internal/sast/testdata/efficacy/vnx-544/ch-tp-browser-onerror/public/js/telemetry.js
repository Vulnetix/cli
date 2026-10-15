window.onerror = function (e, source, lineno, colno) {
  navigator.sendBeacon('/api/telemetry', JSON.stringify({ e: String(e), source, lineno, colno }));
};
