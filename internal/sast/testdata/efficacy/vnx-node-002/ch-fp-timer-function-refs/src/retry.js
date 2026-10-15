const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function schedule(task, delay) {
  const handle = setTimeout(task, delay);
  const tick = setInterval(() => task.run(delay), delay * 2);
  setTimeout(function () { console.log("done " + delay); }, 10);
  return [handle, tick];
}

module.exports = { sleep, schedule };
