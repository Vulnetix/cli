import escape from 'lodash/escape';

const MAP: Record<string, string> = { '<': '&lt;', '>': '&gt;', '&': '&amp;' };

export function encode(s: string): string {
  return s.replace(/[<>&]/g, (c) => MAP[c]);
}

export function encodeAll(s: string): string {
  return s.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

export function viaLodash(s: string): string {
  return escape(s);
}

export function eventName(prop: string): string {
  return prop.replace(/^on/, '').toLowerCase();
}
