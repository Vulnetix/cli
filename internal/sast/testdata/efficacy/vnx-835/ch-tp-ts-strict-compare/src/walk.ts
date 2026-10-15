export function walkTo(start: number, target: number, log: (n: number) => void): void {
  let current = start;
~>  while (current !== target) {
    log(current);
    const next = current + 1;
    log(next);
  }
}
