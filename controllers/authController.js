const User = require('../models/User');
const { signToken } = require('../utils/jwt');
const { hashPassword, comparePassword } = require('../utils/helpers');
const { COOKIE_NAME } = require('../utils/constants');

exports.register = async (req, res) => {
  try {
    const { username, password, displayName, defaultAvatar } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: 'username + password required' });

    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(409).json({ error: 'username exists' });

    const userId = uuid();
    const hashedPassword = await hashPassword(password);

    let avatarPath = '';

    if (req.file) {
      const filename = path.basename(req.file.filename);
      const userUploadDir = path.join(UPLOADS_DIR, 'users', userId);
      await fsp.mkdir(userUploadDir, { recursive: true });

      const newFilePath = path.join(userUploadDir, filename);
      await fsp.rename(req.file.path, newFilePath);

      avatarPath = `users/${userId}/${filename}`;
    }

    const user = new User({
      id: userId,
      username,
      password: hashedPassword,
      displayName: displayName || username,
      defaultAvatar: defaultAvatar || '',
      avatar: avatarPath,
      chatRooms: [],
      createdAt: Date.now(),
      lastSeen: Date.now()
    });

    await user.save();

    const token = signToken({ userId: user.id });
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({
      id: user.id,
      displayName: user.displayName,
      username: user.username,
      defaultAvatar: user.defaultAvatar,
      avatar: user.avatar ? `/uploads/${user.avatar}` : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const match = await comparePassword(password, user.password);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    user.lastSeen = Date.now();
    await user.save();

    const token = signToken({ userId: user.id });
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.logout = async (req, res) => {
  try {
    await User.findOneAndUpdate(
      { id: req.user.userId },
      { lastSeen: Date.now() }
    );
    res.clearCookie(COOKIE_NAME);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};