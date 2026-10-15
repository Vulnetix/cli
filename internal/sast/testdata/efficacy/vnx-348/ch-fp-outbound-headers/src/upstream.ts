import type { IncomingMessage } from "http";

export function upstreamHeaders(req: IncomingMessage): Record<string, string> {
  const remote = req.socket.remoteAddress ?? "";
  return {
    "X-Real-IP": remote,
    "x-forwarded-for": remote,
  };
}
