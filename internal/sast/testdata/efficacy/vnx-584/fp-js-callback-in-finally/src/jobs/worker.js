function run(items) {
  try {
    process(items);
  } finally {
    items.forEach((item) => {
      return release(item);
    });
    setTimeout(function () {
      return cleanup();
    }, 10);
  }
  return items.length;
}
