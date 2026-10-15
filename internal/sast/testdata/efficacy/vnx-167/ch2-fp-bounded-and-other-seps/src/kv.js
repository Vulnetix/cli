export function parsePair(line) {
  const idx = line.indexOf('=');
  const key = line.slice(0, idx);
  const value = line.slice(idx + 1);
  return [key, value];
}

export function parseCreds(line) {
  const [user, ...rest] = line.split(':');
  return { user, password: rest.join(':') };
}

export function firstLabel(line) {
  const [label] = line.split(':');
  return label;
}

const message = "use const [a, b] = s.split(':') carefully";
