const { verifyToken } = require('../utils/jwt');
const { COOKIE_NAME } = require('../utils/constants');

const auth = async (req, res, next) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
};

module.exports = auth;