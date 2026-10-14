const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { scanFile } = require('../av');
const { s3, sqs } = require('../aws');
const db = require('../db');
const log = require('../log');

const router = express.Router();
const upload = multer({ dest: '/tmp/uploads' });

~>router.post('/documents', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'login required' });
    }
    const quota = await db.quotas.findOne({ userId: req.user.id });
    if (quota && quota.used >= quota.limit) {
      log.warn('quota exceeded', { user: req.user.id });
      return res.status(413).end();
    }
    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!['.pdf', '.png', '.jpg'].includes(ext)) {
      return res.status(415).send('unsupported type');
    }
    const digest = crypto.createHash('sha256');
    const buffer = await fs.promises.readFile(req.file.path);
    digest.update(buffer);
    const sha = digest.digest('hex');
    const verdict = await scanFile(req.file.path);
    if (verdict.infected) {
      await fs.promises.unlink(req.file.path);
      metrics.increment('uploads.infected');
      return res.status(422).json({ error: 'file rejected' });
    }
    const key = `${req.user.id}/${sha}${ext}`;
    await s3.putObject({ Bucket: process.env.BUCKET, Key: key, Body: buffer }).promise();
    const doc = await db.documents.insert({
      owner: req.user.id,
      name: sanitizeName(req.file.originalname),
      size: buffer.length,
      sha,
      createdAt: new Date().toISOString(),
    });
    await db.quotas.increment({ userId: req.user.id }, 'used', buffer.length);
    await sqs.sendMessage({ QueueUrl: process.env.QUEUE, MessageBody: JSON.stringify({ id: doc.id }) }).promise();
    audit.record(req.user.id, 'document.upload', { id: doc.id });
    cache.del(`docs:${req.user.id}`);
    notify.user(req.user.id, buildNotice(doc));
    res.set('Location', router.url(doc.id));
    res.status(201).json(serialize(doc));
    await fs.promises.rm(req.file.path, { force: true });
    log.info('uploaded', { id: doc.id, ms: Date.now() - req.startedAt });
    tracing.endSpan(req.span, Object.keys(doc).length);
    events.emit('upload', doc.id);
    webhooks.dispatch(req.user.org, 'document.created', pick(doc, ['id', 'name']));
  } catch (err) {
    log.error('upload failed', { err: err.message });
    Sentry.captureException(err);
    next(err);
  }
});

module.exports = router;
