const sequelize = require('../config/database');
const { User, Role, UserRole } = require('./UsersModel');
const Message = require('./MessagesModel');
const BlacklistedToken = require('./BlacklistedTokenModel');

User.hasMany(Message, { foreignKey: 'UserId' });
Message.belongsTo(User, { foreignKey: 'UserId' });

const db = { sequelize, User, Role, UserRole, Message, BlacklistedToken };

module.exports = db;