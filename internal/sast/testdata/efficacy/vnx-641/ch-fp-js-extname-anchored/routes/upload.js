const path = require("path");

function filter(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!/\.(png|jpe?g)$/i.test(file.originalname)) return cb(new Error("no"));
  const last = file.originalname.split(".").pop();
  const host = req.hostname.split(".")[1];
  cb(null, [".png", ".jpg"].includes(ext) && last !== "php");
}
