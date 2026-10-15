export function load(url) {
  return fetch(url)
    .then((r) => r.json())
    .finally(() => {
      spinner.stop();
      return undefined;
    });
}

export function other() {
  try {
    doWork();
  } finally {
    const items = list.map((x) => {
      return x * 2;
    });
    console.log("return value ignored", items);
  }
  return 1;
}
