import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  max: 5,
~>  keyGenerator: (req: any) =>
    req.headers["x-real-ip"] || req.socket.remoteAddress,
});
