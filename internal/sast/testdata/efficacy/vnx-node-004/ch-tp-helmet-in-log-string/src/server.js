const express = require("express");

~>const app = express();
if (process.env.NODE_ENV === "production") {
  console.warn("TODO: enable helmet() before launch");
}
app.get("/health", (req, res) => res.send("ok"));
app.listen(3000);
