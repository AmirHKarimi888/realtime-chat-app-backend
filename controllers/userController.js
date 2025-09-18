const User = require('../models/User');
const ChatRoom = require('../models/ChatRoom');
const Message = require('../models/Message');
const { getOrCreateChatRoom } = require('./roomController');
const { onlineUsers } = require('../sockets');

exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) return res.status(404).json({ error: 'user not found' });

    user.lastSeen = Date.now();
    await user.save();

    const userResponse = {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      defaultAvatar: user.defaultAvatar,
      avatar: user.avatar ? `/uploads/${user.avatar}` : null,
      chatRooms: user.chatRooms,
      createdAt: user.createdAt,
      isOnline: onlineUsers.has(user.id),
      lastSeen: user.lastSeen
    };

    res.json(userResponse);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({ id: { $ne: req.user.userId } });

    const others = users.map(u => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      defaultAvatar: u.defaultAvatar,
      avatar: u.avatar ? `/uploads/${u.avatar}` : null,
      isOnline: onlineUsers.has(u.id),
      lastSeen: u.lastSeen
    }));

    res.json(others);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.searchUsers = async (req, res) => {
  try {
    const { q } = req.query;

    if (!q) {
      return res.status(400).json({ error: 'Search query must be at least 2 characters' });
    }

    const searchTerm = q.toLowerCase();

    const users = await User.find({
      id: { $ne: req.user.userId },
      $or: [
        { username: { $regex: searchTerm, $options: 'i' } },
        { displayName: { $regex: searchTerm, $options: 'i' } }
      ]
    });

    const results = users.map(u => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      defaultAvatar: u.defaultAvatar,
      avatar: u.avatar ? `/uploads/${u.avatar}` : null,
      isOnline: onlineUsers.has(u.id),
      lastSeen: u.lastSeen
    }));

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getOnlineStatus = async (req, res) => {
  try {
    const users = await User.find({});
    const onlineStatus = {};

    users.forEach(user => {
      onlineStatus[user.id] = onlineUsers.has(user.id);
    });

    res.json(onlineStatus);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};