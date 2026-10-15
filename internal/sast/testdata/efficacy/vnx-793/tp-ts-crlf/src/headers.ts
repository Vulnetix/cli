export function setLocation(res: any, target: string) {
~>  res.setHeader('Location', target.replace('\r\n', ''));
}
