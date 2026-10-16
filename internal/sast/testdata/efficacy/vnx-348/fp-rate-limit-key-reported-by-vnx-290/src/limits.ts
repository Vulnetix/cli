import rateLimit from "express-rate-limit";

// A rate limiter keyed on the header: VNX-290 reports the key function, so
// VNX-348 does not report the same read a second time.
export const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator({ headers, ip }: any) { return headers["x-forwarded-for"] ?? ip },
});

export const loginLimiter = rateLimit({
  max: 5,
  keyGenerator: (req: any) =>
    req.headers["x-real-ip"] || req.socket.remoteAddress,
});
