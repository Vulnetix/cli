import express from "express";

const app = express();

app.use(
~>  express.json({
    strict: true,
    limit: "500mb",
  })
);

app.listen(3000);
