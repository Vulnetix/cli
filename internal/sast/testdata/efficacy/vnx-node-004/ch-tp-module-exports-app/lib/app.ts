import express, { Express } from "express";
import cors from "cors";

export function createApp(): Express {
~>  const app: Express = express();
  app.use(cors());
  app.use(express.json());
  return app;
}
