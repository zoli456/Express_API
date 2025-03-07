const express = require('express');
const { body, param, validationResult } = require('express-validator');
const {  authenticateToken } = require('../middleware');
const Message = require('../models/MessagesModel');
const {User} = require("../models/UsersModel");

const router = express.Router();

const validateMessage = [
    body('content').notEmpty().withMessage('Content is required').isString().withMessage('Content must be a string'),
];

const validateIdParam = [
    param('id').isInt().withMessage('ID must be an integer'),
];

router.post('/', authenticateToken, validateMessage, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { content } = req.body;
    const message = await Message.create({ content, UserId: req.user.id });
    res.json({ message: 'Message created', messageId: message.id });
});
router.get('/', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.findAll({
            include: { model: User, attributes: ['id', 'username'] }, // Include user details
            order: [['createdAt', 'DESC']], // Order by newest messages first
        });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving messages', error: error.message });
    }
})

router.put('/:id', authenticateToken, validateIdParam.concat(validateMessage), async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const message = await Message.findOne({ where: { id: req.params.id, UserId: req.user.id } });
    if (!message) return res.status(403).json({ message: 'Unauthorized to edit this message' });

    message.content = req.body.content;
    await message.save();
    res.json({ message: 'Message updated' });
});

router.delete('/:id', authenticateToken, validateIdParam, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const message = await Message.findOne({ where: { id: req.params.id, UserId: req.user.id } });
    if (!message) return res.status(403).json({ message: 'Unauthorized to delete this message' });

    await message.destroy();
    res.json({ message: 'Message deleted' });
});

module.exports = router;