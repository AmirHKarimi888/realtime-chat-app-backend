const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const roomController = require('../controllers/roomController');
const auth = require('../middleware/auth');

router.get('/me', auth, userController.getCurrentUser);
router.get('/', auth, userController.getAllUsers);
router.get('/search', auth, userController.searchUsers);
router.get('/online-status', auth, userController.getOnlineStatus);
router.get('/chat-rooms', auth, roomController.getUserChatRooms);

module.exports = router;