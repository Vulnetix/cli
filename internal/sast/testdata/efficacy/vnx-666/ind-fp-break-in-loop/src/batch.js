async function handler(req, res) {
  for (const id of req.body.ids) {
    const rec = await store.get(id);
    if (!rec) {
      res.status(404).json({ missing: id });
      break;
    }
  }
  console.log('batch finished');
}
module.exports = handler;
