const path = require("path");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

app.post("/avatar", upload.single("avatar"), (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
~>  if (![".png", ".jpg", ".jpeg"].includes(ext)) {
    return res.status(400).send("images only");
  }
  res.json({ stored: req.file.filename });
});
