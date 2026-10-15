const { parentPort } = require("worker_threads");
const fs = require("fs");

// Runs in a worker thread, off the main event loop.
parentPort.on("message", (msg) => {
  const data = fs.readFileSync(msg.path);
  parentPort.postMessage(data.length);
});

function syncUsers(req, res) {
  return userService.resync(req.body.ids).then((r) => res.json(r));
}

module.exports = { syncUsers };
