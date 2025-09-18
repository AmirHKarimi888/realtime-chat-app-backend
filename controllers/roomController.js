const ChatRoom = require('../models/ChatRoom');
const User = require('../models/User');
const Message = require('../models/Message');
const { generateId } = require('../utils/helpers');
const { onlineUsers } = require('../sockets');

const getOrCreateChatRoom = async (user1Id, user2Id) => {
  try {
    const sortedUsers = [user1Id, user2Id].sort();

    let room = await ChatRoom.findOne({
      participants: { $all: sortedUsers, $size: 2 }
    });

    if (!room) {
      room = new ChatRoom({
        id: generateId(),
        participants: sortedUsers,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });

      await room.save();

      await User.updateMany(
        { id: { $in: sortedUsers } },
        { $addToSet: { chatRooms: room.id } }
      );
    }

    return room;
  } catch (err) {
    console.error('Error getting/creating chat room:', err);
    throw err;
  }
};

exports.getOrCreateChatRoom = getOrCreateChatRoom;

exports.getUserChatRooms = async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const roomsWithDetails = await Promise.all(
      user.chatRooms.map(async (roomId) => {
        const room = await ChatRoom.findOne({ id: roomId });
        if (!room) return null;

        const otherParticipantId = room.participants.find(id => id !== req.user.userId);
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

    res.json(filteredRooms);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};