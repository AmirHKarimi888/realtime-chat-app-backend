const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');

const hashPassword = async (password) => await bcrypt.hash(password, 10);
const comparePassword = async (password, hashedPassword) => await bcrypt.compare(password, hashedPassword);
const generateId = () => uuid();

module.exports = {
  hashPassword,
  comparePassword,
  generateId
};