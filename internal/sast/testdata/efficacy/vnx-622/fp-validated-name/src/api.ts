export function widget (req: Request, res: Response) {
  const cb = req.query.cb as string
  if (!/^[A-Za-z_$][\w$.]*$/.test(cb)) {
    return res.status(400).end()
  }
  res.send(`${cb}(${JSON.stringify(data)})`)
}
