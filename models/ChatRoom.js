const mongoose = require('mongoose');

const chatRoomSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  participants: [{
    type: String,
    ref: 'User',
    required: true
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ChatRoom', chatRoomSchema);