const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const { User, Role, validatePassword } = require('../models/UsersModel');
const {  authenticateToken } = require('../middleware');
const { Op } = require('sequelize');
const router = express.Router();
const BlacklistedToken = require('../models/BlacklistedTokenModel');

const validatePasswordChange = [
    body('oldPassword').notEmpty().withMessage('Old password is required'),
    validatePassword
];

const validateEmailChange = [
    body('newEmail').isEmail().withMessage('Invalid email format'),
];

router.post('/register', [
    body('username').notEmpty().isString().withMessage('Username is required'),
    body('email').isEmail().withMessage('Invalid email address'),
    validatePassword,
    body('roles').isArray().withMessage('Roles must be an array of role names')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, roles } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const user = await User.create({ username, email, password: hashedPassword });

        if (roles?.length) {
            const roleRecords = await Role.findAll({ where: { name: roles } });
            await user.setRoles(roleRecords);
        }

        res.json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error: error.message });
    }
});

router.post('/login', [
    body('identifier').notEmpty().withMessage('Username or email is required'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { identifier, password } = req.body;
    const user = await User.findOne({
        where: {
            [Op.or]: [{ username: identifier }, { email: identifier }]
        }
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
});

router.post('/logout', authenticateToken, async (req, res) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(400).json({ message: 'Token is required' });

    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            return res.status(400).json({ message: 'Invalid token' });
        }

        const expiresAt = new Date(decoded.exp * 1000);
        await BlacklistedToken.create({ token, expiresAt });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging out', error: error.message });
    }
});


router.put('/change-password', authenticateToken, validatePasswordChange, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { oldPassword, newPassword } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!(await bcrypt.compare(oldPassword, user.password))) {
        return res.status(400).json({ message: 'Old password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password updated successfully' });
});

router.put('/change-email', authenticateToken, validateEmailChange, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { newEmail } = req.body;
    const user = await User.findByPk(req.user.id);
    user.email = newEmail;
    await user.save();
    res.json({ message: 'Email updated successfully' });
});

router.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            include: { model: Role, attributes: ['name'] } // Include roles
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            roles: user.Roles.map(role => role.name),
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        });
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving user data', error: error.message });
    }
});

module.exports = router;