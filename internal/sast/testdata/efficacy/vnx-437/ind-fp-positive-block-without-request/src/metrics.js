async function probe(target) {
  if (target.endsWith('.internal.acme.net')) {
    metrics.increment('probe.internal');
    return { skipped: true };
  }
  const res = await fetch(new URL(target).toString());
  return { status: res.status };
}
