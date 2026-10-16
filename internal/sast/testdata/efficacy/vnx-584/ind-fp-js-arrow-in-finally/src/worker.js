async function process(job) {
  try {
    await job.run();
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    job.listeners.forEach((l) => {
      return l.notify(job.id);
    });
    setTimeout(function () {
      return job.release();
    }, 0);
  }
  // finally { return x; } is a bug, do not do that
  const msg = "finally { return null; }";
  return { ok: true, msg };
}

module.exports = { process };
