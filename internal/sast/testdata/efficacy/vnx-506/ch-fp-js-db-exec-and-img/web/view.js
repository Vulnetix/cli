export function render(db, img, b64) {
  const sql = Buffer.from(b64, "base64").toString();
  db.exec(sql);
  img.src = "data:image/png;base64," + b64;
  const text = atob(b64);
  console.log(text);
  return eval("1 + 1");
}
