const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });

app.use((req, res, next) => {
  if (req.path.endsWith(".map") && process.env.NODE_ENV === "production") {
    return res.sendStatus(404);
  }
  next();
});

app.post("/import", upload.single("data"), (req, res) => {
  importRows(req.file.buffer);
  res.json({ name: req.file.originalname });
});
