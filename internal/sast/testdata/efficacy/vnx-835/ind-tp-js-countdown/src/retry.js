function drain(queueName, limit) {
  let attempts = 0;
  const seen = [];
~>  while (attempts < limit) {
    const job = fetchNext(queueName);
    seen.push(job);
    console.log('got', job.id);
  }
  return seen;
}
