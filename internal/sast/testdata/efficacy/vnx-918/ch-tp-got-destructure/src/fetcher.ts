import got from "got";

export async function thumbnail(req, res) {
  const { imageUrl } = req.query;
~>  const img = await got(imageUrl).buffer();
  res.type("png").send(await resize(img));
}
