const http = require('http');
const path = require('path');
const fsp = require('fs/promises');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { v4: uuid } = require('uuid');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 4000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const COOKIE_NAME = 'chat_token';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/chat-app';

// Environment detection
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = isProduction 
  ? 'https://realtime-chat-app-navy-ten.vercel.app' 
  : 'http://localhost:5173';

// Enhanced cookie options for mobile compatibility
const cookieOptions = {
  httpOnly: true,
  secure: isProduction, // true in production, false in development
  sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-site in production
  partitioned: isProduction, // Only in production
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  domain: isProduction ? '.vercel.app' : undefined // Set domain in production
};

// ---------------- MongoDB Connection ----------------
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

mongoose.connection.on('disconnected', () => {
  console.log('⚠️  MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

// ---------------- Mongoose Schemas & Models ----------------
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  displayName: { type: String, required: true },
  avatar: { type: String, default: '' },
  chatRooms: [{ type: String, ref: 'ChatRoom' }],
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
}, {
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      return ret;
    }
  }
});

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

const messageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  roomId: { type: String, required: true, ref: 'ChatRoom' },
  from: { type: String, required: true, ref: 'User' },
  to: { type: String, required: true, ref: 'User' },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isDeleted: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const ChatRoom = mongoose.model('ChatRoom', chatRoomSchema);
const Message = mongoose.model('Message', messageSchema);

// ---------------- Multer Configuration ----------------
const storage = multer.diskStorage({
  destination: async function (req, file, cb) {
    try {
      const userId = req.user?.userId || 'temp';
      const userUploadDir = path.join(UPLOADS_DIR, 'users', userId);
      await fsp.mkdir(userUploadDir, { recursive: true });
      cb(null, userUploadDir);
    } catch (err) {
      cb(err);
    }
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'avatar-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// ---------------- Express ----------------
const app = express();
const server = http.createServer(app);

// Enhanced CORS configuration for mobile
const io = new Server(server, {
  cors: {
    origin: FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"]
  }
});

// Enhanced middleware setup
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cookie');
  next();
});

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  exposedHeaders: ['set-cookie']
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOADS_DIR));

// ---------------- Utilities ----------------
const signToken = payload => jwt.sign(payload, SECRET, { expiresIn: '7d' });
const auth = async (req, res, next) => {
  try {
    // Try to get token from cookies first
    let token = req.cookies[COOKIE_NAME];
    
    // If not in cookies, check Authorization header
    if (!token && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication token required' });
    }
    
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Helper function to get or create a chat room for two users
const getOrCreateChatRoom = async (user1Id, user2Id) => {
  try {
    const sortedUsers = [user1Id, user2Id].sort();
    let room = await ChatRoom.findOne({
      participants: { $all: sortedUsers, $size: 2 }
    });

    if (!room) {
      room = new ChatRoom({
        id: uuid(),
        participants: sortedUsers,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await room.save();

      // Add room to both users' chatRooms array
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

// ---------------- Global Variables ----------------
const onlineUsers = new Map();

// ---------------- Rate Limiting ----------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // Limit each IP to 60 requests per minute
  message: { error: 'Too many messages, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth', authLimiter);
app.use('/api/messages', messageLimiter);

// ---------------- API Routes ----------------
// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ 
      status: 'OK', 
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ 
      status: 'ERROR', 
      database: 'disconnected', 
      error: err.message 
    });
  }
});

// User registration
app.post('/api/auth/register', upload.single('avatar'), async (req, res) => {
  try {
    const { username, password, displayName } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const userId = uuid();
    const hashedPassword = await bcrypt.hash(password, 12);

    let avatarPath = '';
    if (req.file) {
      const filename = path.basename(req.file.filename);
      avatarPath = `users/${userId}/${filename}`;
    }

    const user = new User({
      id: userId,
      username,
      password: hashedPassword,
      displayName: displayName || username,
      avatar: avatarPath,
      chatRooms: [],
      createdAt: new Date(),
      lastSeen: new Date()
    });

    await user.save();

    const token = signToken({ userId: user.id });
    
    // Set HTTP-only cookie
    res.cookie(COOKIE_NAME, token, cookieOptions);
    
    // Also return token in response for mobile clients that might not handle cookies well
    res.status(201).json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar ? `/uploads/${user.avatar}` : null
      },
      token: token // Include token in response for mobile
    });
  } catch (err) {
    console.error('Registration error:', err);
    
    // Clean up uploaded file if error occurred
    if (req.file) {
      try {
        await fsp.unlink(req.file.path);
      } catch (cleanupErr) {
        console.warn('Could not clean up uploaded file:', cleanupErr.message);
      }
    }
    
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last seen
    user.lastSeen = new Date();
    await user.save();

    const token = signToken({ userId: user.id });
    
    // Set HTTP-only cookie
    res.cookie(COOKIE_NAME, token, cookieOptions);
    
    // Also return token in response
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar ? `/uploads/${user.avatar}` : null
      },
      token: token // Include token in response for mobile
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// User logout
app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    await User.findOneAndUpdate(
      { id: req.user.userId },
      { lastSeen: new Date() }
    );
    
    // Clear the cookie
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      domain: isProduction ? '.vercel.app' : undefined
    });
    
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error during logout' });
  }
});

// Get current user
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update last seen
    user.lastSeen = new Date();
    await user.save();

    res.json({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      avatar: user.avatar ? `/uploads/${user.avatar}` : null,
      chatRooms: user.chatRooms,
      createdAt: user.createdAt,
      isOnline: onlineUsers.has(user.id),
      lastSeen: user.lastSeen
    });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users (except current)
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({ id: { $ne: req.user.userId } });

    const others = users.map(u => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      avatar: u.avatar ? `/uploads/${u.avatar}` : null,
      isOnline: onlineUsers.has(u.id),
      lastSeen: u.lastSeen
    }));

    res.json(others);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Search users
app.get('/api/users/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) {
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
      avatar: u.avatar ? `/uploads/${u.avatar}` : null,
      isOnline: onlineUsers.has(u.id),
      lastSeen: u.lastSeen
    }));

    res.json(results);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's chat rooms
app.get('/api/users/chat-rooms', auth, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

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
    console.error('Get chat rooms error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get messages for a room
app.get('/api/messages/room/:roomId', auth, async (req, res) => {
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
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Edit a message
app.put('/api/messages/:messageId', auth, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'Message text is required' });
    }

    const message = await Message.findOne({ id: messageId });
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.from !== req.user.userId) {
      return res.status(403).json({ error: 'You can only edit your own messages' });
    }

    message.text = text;
    message.updatedAt = new Date();
    await message.save();

    io.to(message.from).to(message.to).emit('message:updated', message);

    res.json(message);
  } catch (err) {
    console.error('Edit message error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a message
app.delete('/api/messages/:messageId', auth, async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findOne({ id: messageId });
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.from !== req.user.userId) {
      return res.status(403).json({ error: 'You can only delete your own messages' });
    }

    message.isDeleted = true;
    await message.save();

    io.to(message.from).to(message.to).emit('message:deleted', { id: messageId });

    res.json({ success: true });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large (max 5MB)' });
    }
  }
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------- Socket.IO ----------------
io.use((socket, next) => {
  try {
    // Try to get token from handshake auth
    let token = socket.handshake.auth?.token;
    
    // If not in auth, check cookies
    if (!token && socket.handshake.headers.cookie) {
      const cookies = socket.handshake.headers.cookie.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {});
      
      token = cookies[COOKIE_NAME];
    }
    
    if (!token) {
      return next(new Error('Authentication token required'));
    }
    
    socket.user = jwt.verify(token, SECRET);
    next();
  } catch (error) {
    console.error('Socket auth error:', error.message);
    next(new Error('Invalid authentication token'));
  }
});

io.on('connection', async (socket) => {
  const userId = socket.user.userId;
  console.log('User connected', userId, 'Socket ID:', socket.id);

  socket.join(userId);
  onlineUsers.set(userId, socket.id);
  console.log('Online users:', Array.from(onlineUsers.keys()));

  try {
    await User.findOneAndUpdate(
      { id: userId },
      { lastSeen: new Date() }
    );

    const user = await User.findOne({ id: userId });
    if (user && user.chatRooms.length > 0) {
      user.chatRooms.forEach(roomId => {
        socket.join(roomId);
        console.log(`User ${userId} joined room ${roomId}`);
      });
    }

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

  socket.on('message:send', async ({ to, text }) => {
    try {
      if (!to || !text) {
        return socket.emit('error', { message: 'Missing parameters' });
      }

      const otherUser = await User.findOne({ id: to });
      if (!otherUser) {
        return socket.emit('error', { message: 'Recipient not found' });
      }

      const room = await getOrCreateChatRoom(userId, to);

      socket.join(room.id);
      const recipientSocket = io.sockets.sockets.get(onlineUsers.get(to));
      if (recipientSocket) {
        recipientSocket.join(room.id);
      }

      const msg = new Message({
        id: uuid(),
        roomId: room.id,
        from: userId,
        to,
        text,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await msg.save();

      await ChatRoom.findOneAndUpdate(
        { id: room.id },
        { updatedAt: new Date() }
      );

      io.to(room.id).emit('message:new', msg);

      io.to(userId).emit('chatlist:refresh');
      io.to(to).emit('chatlist:refresh');

    } catch (err) {
      console.error('Error sending message:', err);
      socket.emit('error', {
        message: 'Failed to send message',
        error: err.message
      });
    }
  });

  socket.on('message:edit', async ({ messageId, text }) => {
    try {
      if (!messageId || !text) return;

      const message = await Message.findOne({ id: messageId });
      if (!message) return;

      if (message.from !== userId) return;

      message.text = text;
      message.updatedAt = new Date();
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
        { lastSeen: new Date() }
      );

      io.emit('user:offline', userId);
    } catch (err) {
      console.error('Error updating user status on disconnect:', err);
    }
  });
});

// ---------------- Boot ----------------
(async () => {
  try {
    await fsp.mkdir(UPLOADS_DIR, { recursive: true });
    server.listen(PORT, () => {
      console.log(`✅ Chat application running on http://localhost:${PORT}`);
      console.log(`📱 Frontend URL: ${FRONTEND_URL}`);
      console.log(`🔐 Cookie name: ${COOKIE_NAME}`);
      console.log(`🌐 Environment: ${isProduction ? 'Production' : 'Development'}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();