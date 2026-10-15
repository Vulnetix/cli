import express from "express";
import cors from "cors";

~>const server = express();
server.use(cors());
server.use(express.json());
server.get("/items", (req, res) => res.json([]));
server.listen(process.env.PORT || 8080);
