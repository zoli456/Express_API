const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const { body } = require("express-validator");

const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: { isEmail: true }
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    }
});

const Role = sequelize.define('Role', {
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    }
});

const UserRole = sequelize.define('UserRole', {}, { timestamps: false });

User.belongsToMany(Role, { through: UserRole });
Role.belongsToMany(User, { through: UserRole });

const validatePassword = body('password')
  .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
  .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
  .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
  .matches(/\d/).withMessage('Password must contain at least one number')
  .matches(/[\W_]/).withMessage('Password must contain at least one special character');


module.exports = { User, Role, UserRole, validatePassword };