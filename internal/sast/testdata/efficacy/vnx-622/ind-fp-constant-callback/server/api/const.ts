export function boot(req: any, res: any) {
  const data = JSON.stringify({ v: 2 })
  // res.send(req.query.callback + '(' + data + ')')  insecure example
  const note = "res.send(req.query.callback + '(')"
  res.send('window.onBoot(' + data + ');')
  res.send(`initApp(${data})`)
}
