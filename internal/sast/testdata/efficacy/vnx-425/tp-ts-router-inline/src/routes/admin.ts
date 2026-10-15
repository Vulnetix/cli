import { Router, Request, Response } from 'express'
import { db } from '../db'

export const router = Router()

~>router.get('/admin/stats', async (req: Request, res: Response) => {
  const rows = await db.query('select count(*) from orders')
  res.json(rows)
})

~>router.put('/management/flags', function (req, res) {
  db.setFlags(req.body)
  res.end()
})
