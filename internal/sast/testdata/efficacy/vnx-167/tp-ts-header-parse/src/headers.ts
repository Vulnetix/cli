export function parseParam(param: string): [string, string] {
~>  const [key, val] = param.trim().split(`=`);
  return [key, val];
}
