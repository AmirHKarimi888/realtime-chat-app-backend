const { verifyToken } = require('../utils/jwt');
const User = require('../models/User');
const Message = require('../models/Message');
const ChatRoom = require('../models/ChatRoom');
const { COOKIE_NAME } = require('../utils/constants');
const { sendMessage } = require('../controllers/messageController');
const { getOrCreateChatRoom } = require('../controllers/roomController');

const onlineUsers = new Map();

const configureSockets = (io) => {
  io.use((socket, next) => {
    let token = socket.handshake.auth?.token;
    if (!token && socket.handshake.headers.cookie) {
      const cookies = Object.fromEntries(socket.handshake.headers.cookie.split(';').map(c => {
        const [k, ...v] = c.trim().split('=');
        return [k, v.join('=')];
      }));
      token = cookies[COOKIE_NAME];
    }
    if (!token) return next(new Error('Missing token'));
    try {
      socket.user = verifyToken(token);
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', async (socket) => {
    const userId = socket.user.userId;
    console.log('User connected', userId);

    socket.join(userId);
    onlineUsers.set(userId, socket.id);

    try {
      await User.findOneAndUpdate(
        { id: userId },
        { lastSeen: Date.now() }
      );

      io.emit('user:online', userId);

      const onlineStatus = {};
      onlineUsers.forEach((_, id) => {
        onlineStatus[id] = true;
      });
      socket.emit('users:online-status', onlineStatus);
    } catch (err) {
      console.error('Error updating user status:', err);
    }

    socket.on('chatlist:get', async () => {
      try {
        const user = await User.findOne({ id: userId });
        if (!user) return;

        const roomsWithDetails = await Promise.all(
          user.chatRooms.map(async (roomId) => {
            const room = await ChatRoom.findOne({ id: roomId });
            if (!room) return null;

            const otherParticipantId = room.participants.find(id => id !== userId);
            const otherUser = await User.findOne({ id: otherParticipantId });

            if (!otherUser) return null;

            const lastMessage = await Message.findOne(
              { roomId, isDeleted: false },
              {},
              { sort: { createdAt: -1 } }
            );

            return {
              roomId: room.id,
              participant: {
                id: otherUser.id,
                username: otherUser.username,
                displayName: otherUser.displayName,
                avatar: otherUser.avatar ? `/uploads/${otherUser.avatar}` : null,
                defaultAvatar: otherUser.defaultAvatar,
                isOnline: onlineUsers.has(otherUser.id),
                lastSeen: otherUser.lastSeen
              },
              lastMessage: lastMessage ? {
                id: lastMessage.id,
                text: lastMessage.text,
                createdAt: lastMessage.createdAt,
                from: lastMessage.from
              } : null,
              unreadCount: 0,
              updatedAt: room.updatedAt
            };
          })
        );

        const filteredRooms = roomsWithDetails.filter(room => room !== null);
        filteredRooms.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

        socket.emit('chatlist:updated', filteredRooms);
      } catch (err) {
        console.error('Error fetching chat list:', err);
        socket.emit('error', { message: 'Failed to fetch chat list' });
      }
    });

    socket.on('messages:get', async ({ roomId, limit = 50, before = null }) => {
      try {
        if (!roomId) return;

        const user = await User.findOne({ id: userId });
        if (!user.chatRooms.includes(roomId)) {
          socket.emit('error', { message: 'Access denied to this chat room' });
          return;
        }

        const query = {
          roomId,
          isDeleted: false
        };

        if (before) {
          query.createdAt = { $lt: new Date(before) };
        }

        const messages = await Message.find(query)
          .sort({ createdAt: -1 })
          .limit(limit)
          .exec();

        const orderedMessages = messages.reverse();

        socket.emit('messages:response', {
          roomId,
          messages: orderedMessages,
          hasMore: messages.length === limit
        });
      } catch (err) {
        console.error('Error fetching messages:', err);
        socket.emit('error', { message: 'Failed to fetch messages' });
      }
    });

    socket.on('message:send', async (data) => {
      await sendMessage(io, socket, data);
    });

    socket.on('message:edit', async ({ messageId, text }) => {
      try {
        if (!messageId || !text) return;

        const message = await Message.findOne({ id: messageId });
        if (!message) return;

        if (message.from !== userId) return;

        message.text = text;
        message.updatedAt = Date.now();
        await message.save();

        io.to(message.from).to(message.to).emit('message:updated', message);
      } catch (err) {
        console.error('Error editing message:', err);
      }
    });

    socket.on('message:delete', async ({ messageId }) => {
      try {
        if (!messageId) return;

        const message = await Message.findOne({ id: messageId });
        if (!message) return;

        if (message.from !== userId) return;

        if (message.isDeleted) {
          console.log('Message already deleted, ignoring request');
          return;
        }

        message.isDeleted = true;
        await message.save();

        socket.to(message.from).to(message.to).emit('message:deleted', { id: messageId });
      } catch (err) {
        console.error('Error deleting message:', err);
      }
    });

    socket.on('typing:start', ({ to }) => {
      socket.to(to).emit('typing:start', { from: userId });
    });

    socket.on('typing:stop', ({ to }) => {
      socket.to(to).emit('typing:stop', { from: userId });
    });

    socket.on('disconnect', async () => {
      console.log('User disconnected', userId);

      onlineUsers.delete(userId);

      try {
        await User.findOneAndUpdate(
          { id: userId },
          { lastSeen: Date.now() }
        );

        io.emit('user:offline', userId);
      } catch (err) {
        console.error('Error updating user status on disconnect:', err);
      }
    });
  });
};

module.exports = {
  configureSockets,
  onlineUsers
};