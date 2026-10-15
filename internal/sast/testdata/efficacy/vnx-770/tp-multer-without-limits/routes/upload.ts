import multer from 'multer'
import path from 'path'

~>const upload = multer({ dest: 'uploads/' })
~>const toDisk = multer({
  storage: multer.diskStorage({
    destination: (req: any, file: any, cb: any) => {
      cb(null, path.resolve('uploads'))
    }
  })
})
~>const anything = multer()

export { upload, toDisk, anything }
