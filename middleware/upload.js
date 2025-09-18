const fsp = require('fs/promises');
const path = require('path');
const { UPLOADS_DIR } = require('../utils/constants');

const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large (max 5MB)' });
    }
  }
  res.status(500).json({ error: error.message });
};

const cleanupTempFiles = async (req, res, next) => {
  if (req.file) {
    try {
      await fsp.unlink(req.file.path);
    } catch (cleanupErr) {
      console.warn('Could not clean up uploaded file:', cleanupErr.message);
    }
  }
  next();
};

module.exports = {
  handleUploadError,
  cleanupTempFiles
};