const express = require("express");
const cors = require("cors");

const app = express();

app.use(
  cors({
    credentials: true,
    origin(origin, callback) {
~>      if (!origin || origin.indexOf("acme-corp.com") !== -1) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
  })
);

module.exports = app;
