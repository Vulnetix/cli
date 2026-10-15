import { Request, Response } from 'express'
import { Parser } from '@json2csv/plainjs'
import { Order } from '../models/order'

export async function downloadOrders(req: Request, res: Response) {
  const orders = await Order.find({ customer: req.user.id }).lean()
  const parser = new Parser({ fields: ['id', 'shippingName', 'note'] })
~>  const body = parser.parse(orders)
  res.header('Content-Type', 'text/csv')
  res.attachment(`orders-${Date.now()}.csv`)
  res.send(body)
}
