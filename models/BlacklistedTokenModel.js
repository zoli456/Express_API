const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const BlacklistedToken = sequelize.define('BlacklistedToken', {
    token: {
        type: DataTypes.STRING,
        allowNull: false,
        primaryKey: true
    },
    expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
    }
});

module.exports = BlacklistedToken;