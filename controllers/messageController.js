const Message = require('../models/Message');
const User = require('../models/User');
const ChatRoom = require('../models/ChatRoom');
const { generateId } = require('../utils/helpers');
const { getOrCreateChatRoom } = require('./roomController');

exports.getRoomMessages = async (req, res) => {
  try {
    const { roomId } = req.params;

    const user = await User.findOne({ id: req.user.userId });
    if (!user.chatRooms.includes(roomId)) {
      return res.status(403).json({ error: 'Access denied to this chat room' });
    }

    const messages = await Message.find({
      roomId,
      isDeleted: false
    }).sort({ createdAt: 1 });

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.editMessage = async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;

    if (!text) return res.status(400).json({ error: 'Message text is required' });

    const message = await Message.findOne({ id: messageId });
    if (!message) return res.status(404).json({ error: 'Message not found' });

    if (message.from !== req.user.userId) {
      return res.status(403).json({ error: 'You can only edit your own messages' });
    }

    message.text = text;
    message.updatedAt = Date.now();
    await message.save();

    res.json(message);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.deleteMessage = async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findOne({ id: messageId });
    if (!message) return res.status(404).json({ error: 'Message not found' });

    if (message.from !== req.user.userId) {
      return res.status(403).json({ error: 'You can only delete your own messages' });
    }

    message.isDeleted = true;
    await message.save();

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.sendMessage = async (io, socket, { to, text }) => {
  try {
    if (!to || !text) return;

    const otherUser = await User.findOne({ id: to });
    if (!otherUser) return;

    const room = await getOrCreateChatRoom(socket.user.userId, to);

    const msg = new Message({
      id: generateId(),
      roomId: room.id,
      from: socket.user.userId,
      to,
      text,
      createdAt: Date.now(),
      updatedAt: Date.now()
    });

    await msg.save();

    await ChatRoom.findOneAndUpdate(
      { id: room.id },
      { updatedAt: Date.now() }
    );

    io.to(socket.user.userId).to(to).emit('message:new', msg);
    io.to(socket.user.userId).emit('chatlist:refresh');
    io.to(to).emit('chatlist:refresh');
  } catch (err) {
    console.error('Error sending message:', err);
  }
};