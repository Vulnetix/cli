export function compute(row: Record<string, number>, formula: string): number {
  const names = Object.keys(row).join(", ");
~>  const fn = new Function(...Object.keys(row), `return (${formula});`);
~>  const viaEval = eval(`(function (${names}) { return ${formula}; })`);
  return fn(...Object.values(row)) ?? viaEval;
}
