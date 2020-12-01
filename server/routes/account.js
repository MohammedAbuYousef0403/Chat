const express    = require('express')
const router     = express.Router()
const path       = require('path')
const multer     = require('multer')

const controller = require('../controllers/accountController')
const auth       = require('../middlewares/auth')

const storage = multer.diskStorage({
    destination: 'public/uploads/',
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname))
    }
})

const upload = multer({
    limits: { fileSize: 1024 * 1024 },
    storage: storage ,
    fileFilter: (req, file, cb) => {
        let fileTypes = /jpeg|jpg|png/
        let mimeType = fileTypes.test(file.mimetype)
        let extname = fileTypes.test(path.extname(file.originalname).toLowerCase())
        if (mimeType && extname)  return cb(null, true)
        cb(new Error('This file is not allowed to be uploaded'))
    },
})

router.post('/', [auth.authenticated, upload.single('avatar')], controller.profile)

router.post('/password', auth.authenticated, controller.password)

module.exports = router
