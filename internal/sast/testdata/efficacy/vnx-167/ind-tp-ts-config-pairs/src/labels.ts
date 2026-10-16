export interface Labels {
  [key: string]: string;
}

export function parseLabels(spec: string): Labels {
  const labels: Labels = {};
  for (const pair of spec.split(',')) {
~>    const [key, value] = pair.split('=').map((s) => s.trim());
    if (key) {
      labels[key] = value;
    }
  }
  return labels;
}

export function tokenFromHeader(line: string): string {
~>  const [, token] = line.split(':');
  return token.trim();
}
