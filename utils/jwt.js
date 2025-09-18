const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const signToken = (payload) => jwt.sign(payload, SECRET, { expiresIn: '7d' });
const verifyToken = (token) => jwt.verify(token, SECRET);

module.exports = {
  signToken,
  verifyToken
};