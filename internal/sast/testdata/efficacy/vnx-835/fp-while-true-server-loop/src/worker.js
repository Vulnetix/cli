async function worker(queue) {
  while (true) {
    const job = await queue.next();
    await job.run();
  }
}

function spin() {
  for (;;) {
    tick();
  }
}
