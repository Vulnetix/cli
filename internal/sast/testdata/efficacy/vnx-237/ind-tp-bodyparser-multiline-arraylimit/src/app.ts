import bodyParser from "body-parser";
import express from "express";

const app = express();
app.use(
  bodyParser.urlencoded({
    extended: true,
~>    arrayLimit: Infinity,
  }),
);

export default app;
