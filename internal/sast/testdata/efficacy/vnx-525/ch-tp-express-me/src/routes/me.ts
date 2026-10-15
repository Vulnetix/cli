import { Router } from "express";
import { requireAuth } from "../middleware/auth";

export const router = Router();

router.get("/api/me", requireAuth, (req, res) => {
~>  res.setHeader("Cache-Control", "public, max-age=600");
  res.json({ id: req.user.id, email: req.user.email });
});
