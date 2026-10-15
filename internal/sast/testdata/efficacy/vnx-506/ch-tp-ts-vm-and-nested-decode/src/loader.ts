import * as vm from "vm";

export function load(src: string, sandbox: object): unknown {
~>  return vm.runInNewContext(atob(src), sandbox);
}

export function legacy(s: string): void {
~>  eval(decodeURIComponent(escape(atob(s))));
}
