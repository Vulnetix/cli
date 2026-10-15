const express = require("express");
const app = express();

app.use(express.urlencoded({ extended: true, parameterLimit: 1000 }));
app.use(express.json({ limit: "100kb" }));
