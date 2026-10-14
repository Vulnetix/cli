export function compileRule(body) {
~>  const fn = new Function("ctx", "return (" + body + ");");
  return fn;
}

export function compileFilter(src) {
~>  return Function(`return ${src}`)();
}
