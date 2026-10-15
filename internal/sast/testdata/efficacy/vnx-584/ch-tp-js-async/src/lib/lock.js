export async function withLock(lock, fn) {
  await lock.acquire();
  try {
    return await fn();
  } catch (err) {
    console.error(err);
    throw err;
  } finally {
    lock.release();
~>    return null;
  }
}
