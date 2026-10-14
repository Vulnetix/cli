async function useA() {
  const a = await import('./a.js');
  return a.value();
}

module.exports = { useA, value: () => 2 };
