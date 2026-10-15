const express = require("express");
const { body, validationResult } = require("express-validator");
const app = express();

app.post(
  "/comment",
  body("text").isLength({ min: 1, max: 500 }).escape(),
  (req, res) => {
    validationResult(req).throw();
    comments.add(req.body.text);
    res.status(201).end();
  }
);
