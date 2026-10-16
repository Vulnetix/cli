export function compile(body, names) {
  const args = names.join(",");
~>  const fn = new Function(args, "return (" + body + ");");
  return (...vals) => fn(...vals);
}

export function once(src) {
~>  return Function(`return ${src}`)();
}
