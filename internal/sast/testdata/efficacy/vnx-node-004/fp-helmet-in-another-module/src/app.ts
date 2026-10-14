import express from "express";
import { security } from "./middleware/security";

const app = express();
security(app);
export default app;
