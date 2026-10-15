export function cleanPath(file: string): string {
~>  return file.replace('../', '');
}

export function stripScript(input: string): string {
~>  return input.replace(/<script>/gi, '');
}

export function cleanUrl(url: string): string {
~>  return url.replaceAll('javascript:', '');
}

export function cleanAll(p: string): string {
~>  return p.replace(/\.\.\//g, "");
}
