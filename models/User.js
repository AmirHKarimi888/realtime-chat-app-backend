const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  displayName: { type: String, required: true },
  defaultAvatar: { type: String, default: '' },
  avatar: { type: String, default: '' },
  chatRooms: [{ type: String, ref: 'ChatRoom' }],
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);