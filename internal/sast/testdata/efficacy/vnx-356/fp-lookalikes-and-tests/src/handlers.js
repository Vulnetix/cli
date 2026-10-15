// setPermissionRequestHandler((wc, permission, cb) => cb(true)) grants everything
const doc = "app.on('certificate-error', ...) then callback(true)";

function onConfirm(callback) {
  callback(true);
}

emitter.on('request', (event, data, callback) => {
  callback(true);
});
