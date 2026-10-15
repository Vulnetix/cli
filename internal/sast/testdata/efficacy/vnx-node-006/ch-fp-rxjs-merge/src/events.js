import { merge, fromEvent } from "rxjs";

export function inputEvents(req, el) {
  const clicks = fromEvent(el, "click");
  const keys = fromEvent(el, "keyup");
  const chunks = fromEvent(req.body, "data");
  return merge(clicks, keys, chunks, fromEvent(req.query.stream, "end"));
}
