const express = require('express');
const router = express.Router();
const messageController = require('../controllers/messageController');
const auth = require('../middleware/auth');
const { messageLimiter } = require('../config/rateLimiter');

router.get('/room/:roomId', auth, messageController.getRoomMessages);
router.put('/:messageId', auth, messageLimiter, messageController.editMessage);
router.delete('/:messageId', auth, messageLimiter, messageController.deleteMessage);

module.exports = router;