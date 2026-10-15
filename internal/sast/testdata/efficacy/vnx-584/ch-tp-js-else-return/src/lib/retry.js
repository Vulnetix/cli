export function attempt(task) {
  try {
    return task.run();
  } finally {
    task.release();
~>    if (task.cancelled) return false; else return true;
  }
}
