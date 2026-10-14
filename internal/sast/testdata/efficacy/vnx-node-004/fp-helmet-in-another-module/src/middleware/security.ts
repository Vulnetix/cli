import helmet from "helmet";
import type { Express } from "express";

export function security(app: Express) {
  app.use(helmet());
}
