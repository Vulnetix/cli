export function compileFormula(body: string, args: string[]): (...xs: number[]) => number {
~>  const fn = new Function(...args, body);
  return fn as (...xs: number[]) => number;
}

export function evaluateField(field: { expr: string }, row: Record<string, unknown>): unknown {
~>  return Function("row", "return " + field.expr)(row);
}
