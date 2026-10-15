const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;
export const clean = (s) => s.replace(BIDI, '');
