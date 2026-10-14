import express, { Express } from "express";
import cors from "cors";

~>export const app: Express = express();
app.use(cors());
app.use(express.json());
