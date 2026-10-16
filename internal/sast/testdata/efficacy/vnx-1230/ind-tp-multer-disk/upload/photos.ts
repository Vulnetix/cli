import multer from 'multer';

// store profile photos on disk
~>export const photoStorage = multer.diskStorage({
  destination: 'uploads/photos',
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
export const uploadPhoto = multer({ storage: photoStorage, limits: { fileSize: 5e6 } });
