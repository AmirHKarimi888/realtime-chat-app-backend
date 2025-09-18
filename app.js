const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fsp = require('fs/promises');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const messageRoutes = require('./routes/messages');
const { handleUploadError } = require('./middleware/upload');
const { UPLOADS_DIR } = require('./utils/constants');

const app = express();

// Create uploads directory if it doesn't exist
(async () => {
  try {
    await fsp.mkdir(UPLOADS_DIR, { recursive: true });
  } catch (err) {
    console.error('Failed to create uploads directory:', err);
  }
})();

// Middleware
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(UPLOADS_DIR));

// Routes
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/messages', messageRoutes);

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const mongoose = require('mongoose');
    await mongoose.connection.db.admin().ping();
    res.json({ status: 'OK', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', database: 'disconnected', error: err.message });
  }
});

// Error handling for file uploads
app.use(handleUploadError);

module.exports = app;