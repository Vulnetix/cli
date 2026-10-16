const express = require("express");
const app = express();

app.use(express.json({ limit: "1mb" }));
~>app.use(express.urlencoded({ extended: true, parameterLimit: 1000000 }));
app.use("/api", require("./routes"));

app.listen(3000);
