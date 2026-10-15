export function applyCoupon(req: Request, res: Response) {
~>  const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')
  const discount = parseInt(couponData[1], 10)
  res.json({ discount })
}
