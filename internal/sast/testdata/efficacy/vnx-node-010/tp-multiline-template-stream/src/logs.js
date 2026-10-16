const fs = require("fs");
const path = require("path");
const express = require("express");
const app = express();

app.get("/logs", (req, res) => {
~>  const stream = fs.createReadStream(
    `./logs/${req.query.day}.log`
  );
  stream.pipe(res);
});

app.get("/files", (req, res) => {
~>  fs.readFile(path.join(__dirname, "files", req.query.name), (err, data) => {
    if (err) return res.sendStatus(404);
    res.send(data);
  });
});
