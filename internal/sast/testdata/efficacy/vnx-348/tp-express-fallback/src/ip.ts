import rateLimit from "express-rate-limit";

export function clientIp(req: any): string {
~>  return (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
}

export const limiter = rateLimit({
  windowMs: 60_000,
~>  keyGenerator({ headers, ip }: any) { return headers["X-Forwarded-For"] ?? ip },
});

export function audit(req: any) {
  const who =
~>    req.header("X-Client-IP") ||
    req.connection.remoteAddress;
  log.info("login from %s", who);
}
