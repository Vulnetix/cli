declare function eval(x: string): any;

declare module "sandbox-lib" {
  export function evaluate(expr: string): number;
}
