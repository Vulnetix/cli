import DOMPurify from "dompurify";

export function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function clean(html) {
  return DOMPurify.sanitize(html, { FORBID_TAGS: ["script"] });
}
