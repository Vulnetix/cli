const cors = require("cors");

app.use(
  cors({
    credentials: true,
    origin(origin, callback) {
~>      if (!origin || origin.indexOf("example.com") !== -1) return callback(null, true);
      callback(new Error("blocked"));
    },
  }),
);

app.use((req, res, next) => {
~>  if (req.headers.origin && req.headers.origin.startsWith("https://app.example.com")) {
    res.set("Access-Control-Allow-Origin", req.headers.origin);
    res.set("Access-Control-Allow-Credentials", "true");
  }
  next();
});
