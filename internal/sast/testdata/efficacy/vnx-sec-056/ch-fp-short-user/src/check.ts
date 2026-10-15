export const isUserToken = (t: string) => t.startsWith("sntryu_") && t.length === 71;
const sample = "sntryu_abc123";
