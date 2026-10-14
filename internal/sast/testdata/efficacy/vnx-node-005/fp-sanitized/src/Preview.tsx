import DOMPurify from "dompurify";
import sanitizeHtml from "sanitize-html";

export function Preview({ md }: { md: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(md) }} />;
}

export function show(el: HTMLElement, html: string) {
  el.innerHTML = DOMPurify.sanitize(html);
  el.innerHTML = sanitizeHtml(html, { allowedTags: ["b"] });
}
