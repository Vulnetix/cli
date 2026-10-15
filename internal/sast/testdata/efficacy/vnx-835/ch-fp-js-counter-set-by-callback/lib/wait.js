const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForAll(emitter, n) {
  let done = 0;
  emitter.on('finished', () => { done++; });
  while (done < n) {
    await sleep(50);
  }
}

module.exports = { waitForAll };
