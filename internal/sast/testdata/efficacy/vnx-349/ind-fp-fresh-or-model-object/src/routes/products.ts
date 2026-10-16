import { Router } from "express";
import { Product } from "../models/product";

const router = Router();

router.put("/products/:id", async (req, res) => {
  const filters = Object.assign({}, req.query);
  const product = await Product.findById(req.params.id);
  Object.assign(product, req.body);
  await product.save();
  res.json({ product, filters });
});

export default router;
