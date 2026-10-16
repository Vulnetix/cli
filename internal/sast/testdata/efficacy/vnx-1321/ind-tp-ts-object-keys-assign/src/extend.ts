export function extend(dst: any, src: any): any {
  Object.keys(src).forEach((k) => {
    if (typeof src[k] === 'object' && src[k] !== null) {
~>      Object.assign(dst[k] || {}, src[k]);
    } else {
      dst[k] = src[k];
    }
  });
  return dst;
}
