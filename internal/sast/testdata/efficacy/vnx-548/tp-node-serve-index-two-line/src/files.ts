import serveIndex from 'serve-index';
import express from 'express';

const uploads = path.join(__dirname, 'uploads');
~>const listing = serveIndex(uploads, { view: 'details' });
router.use('/uploads', express.static(uploads), listing);
