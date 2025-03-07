const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { authenticateToken, checkAdmin } = require('../middleware');
const { Message, User } = require('../models/MessagesModel');

const router = express.Router();

const validateMessage = [
    body('content').notEmpty().withMessage('Content is required').isString().withMessage('Content must be a string'),
];

const validateIdParam = [
    param('id').isInt().withMessage('ID must be an integer'),
];

router.delete('/messages/:id', authenticateToken, checkAdmin, validateIdParam, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const message = await Message.findByPk(req.params.id);
    if (!message) return res.status(404).json({ message: 'Message not found' });

    await message.destroy();
    res.json({ message: 'Message deleted by admin' });
});

router.delete('/users/:id', authenticateToken, checkAdmin, validateIdParam, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    await User.destroy({ where: { id: req.params.id } });
    res.json({ message: 'User deleted' });
});

router.delete('/messages/all', authenticateToken, checkAdmin, async (req, res) => {
    try {
        await Message.destroy({ where: {} }); // Deletes all messages
        res.json({ message: 'All messages deleted by admin' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting messages', error: error.message });
    }
});

module.exports = router;
