function harden() {
  process.umask(0o022);
  const previous = process.umask(0);
  process.umask(previous);
  return previous;
}

module.exports = { harden };
