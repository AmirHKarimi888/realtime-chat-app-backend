const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const upload = require('../config/multer');
const { authLimiter } = require('../config/rateLimiter');
const { cleanupTempFiles } = require('../middleware/upload');

router.post('/', authLimiter, upload.single('avatar'), authController.register, cleanupTempFiles);
router.post('/login', authLimiter, authController.login);
router.post('/logout', authController.logout);

module.exports = router;