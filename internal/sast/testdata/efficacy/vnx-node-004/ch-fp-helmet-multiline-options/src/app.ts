import express, { type Express } from "express";
import helmet from "helmet";

export const app: Express = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: { defaultSrc: ["'self'"] },
    },
  }),
);
