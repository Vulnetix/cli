function preview(imageBytes) {
  console.log("preview", Buffer.from(imageBytes).toString("base64").length);
  const thumb = btoa(fileName);
  console.debug(thumb);
}
