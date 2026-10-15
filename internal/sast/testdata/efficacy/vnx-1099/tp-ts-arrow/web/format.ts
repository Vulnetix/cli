export const escape_html = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

~>export const escapeHtml = async (s: string): Promise<string> => {
  return s.replace(/</g, "&lt;");
};
