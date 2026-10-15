export async function retry(fn: () => Promise<void>, attempts: number): Promise<void> {
  let tries = 0;
~>  while (tries != attempts) {
    try {
      await fn();
    } catch (e) {
      console.warn(`attempt ${tries} failed`, e);
    }
  }
}
