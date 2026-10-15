import { Router } from "express";
import { prisma } from "../db";

export const router = Router();

router.post("/signup", async (req, res) => {
  const user = await prisma.user.create({
    data: {
      email: req.body.email,
~>      password: req.body.password,
    },
  });
  res.status(201).json({ id: user.id });
});
