const { v4: uuidv4 } = require('uuid');
const db = require('../database/db');
const { encrypt, decrypt } = require('../utils/encryption');
const logger = require('../utils/logger');
const { validateRoomInput, sanitizeInput } = require('../utils/validation');
const { rateLimit } = require('express-rate-limit');
const { blockedNames, religiousTerms } = require('../config/blockedNames');

const ROOM_CONSTANTS = {
    MAX_USERS: 1000,
    MIN_PASSWORD_LENGTH: 6,
    ROOM_CODE_LENGTH: 20,
    ROOM_INACTIVE_TIMEOUT: 24 * 60 * 60 * 1000,
    USERNAME_REGEX: /^[a-zA-Z0-9_-]{3,20}$/,
    RESERVED_USERNAMES: [...blockedNames, ...religiousTerms],
    ROOM_LIFETIMES: {
        ONE_DAY: 24 * 60 * 60 * 1000,
        ONE_MONTH: 30 * 24 * 60 * 60 * 1000,
        ONE_YEAR: 365 * 24 * 60 * 60 * 1000,
        PERMANENT: -1
    },
    DEFAULT_CATEGORIES: ['general', 'software', 'chat', 'gaming', 'support', 'other']
};

const limiter = rateLimit({
    windowMs: 3 * 60 * 1000,
    max: 50,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again after a few minutes',
});

const userLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 20,
    keyGenerator: (req) => `${req.body.userId}_${req.ip}`,
    message: 'Too many requests from this user, please try again after a minute',
});

async function generateRoomCode() {
    try {
        let roomCode;
        let roomExists;
        let attempts = 0;
        const MAX_ATTEMPTS = 10;

        do {
            if (attempts >= MAX_ATTEMPTS) {
                throw new Error('Maximum attempts exceeded while generating room code');
            }

            roomCode = uuidv4().substring(0, 32);
            roomExists = await isRoomExists(roomCode);
            attempts++;
        } while (roomExists);

        return roomCode;
    } catch (error) {
        logger.error('Error generating room code:', error);
        throw new Error('Error occurred while generating room code');
    }
}

async function isRoomExists(roomId) {
    try {
        if (!roomId || typeof roomId !== 'string') {
            throw new Error('Invalid room ID');
        }
        const result = await db.get(`rooms.${roomId}`);
        return !!result;
    } catch (error) {
        logger.error('Error checking room existence:', error);
        throw error;
    }
}

exports.createRoom = [userLimiter, async (req, res) => {
    try {
        const { userId, type, password, roomName, lifetime, category } = req.body;

        if (!userId || !ROOM_CONSTANTS.USERNAME_REGEX.test(userId)) {
            return res.status(400).json({ error: 'Invalid username format' });
        }

        const sanitizedUserId = sanitizeInput(userId).toLowerCase();
        if (ROOM_CONSTANTS.RESERVED_USERNAMES.includes(sanitizedUserId)) {
            return res.status(400).json({ error: 'This username is not allowed' });
        }

        if (!validateRoomInput({ userId, type, password })) {
            return res.status(400).json({ error: 'Invalid input parameters' });
        }

        if (!roomName || roomName.trim().length < 3 || roomName.trim().length > 50) {
            return res.status(400).json({ error: 'Room name must be between 3 and 50 characters' });
        }

        if (!lifetime || !Object.values(ROOM_CONSTANTS.ROOM_LIFETIMES).includes(parseInt(lifetime))) {
            return res.status(400).json({ error: 'Invalid room lifetime' });
        }

        if (category && !ROOM_CONSTANTS.DEFAULT_CATEGORIES.includes(category.toLowerCase())) {
            return res.status(400).json({ error: 'Invalid room category' });
        }

        const sanitizedRoomName = sanitizeInput(roomName);

        const roomId = await generateRoomCode();
        const roomInfo = {
            users: ["System"],
            owner: sanitizedUserId,
            messages: [],
            typingUsers: [],
            type: type || 'public',
            createdAt: new Date().toISOString(),
            lastActivity: new Date().toISOString(),
            roomName: sanitizedRoomName,
            lifetime: parseInt(lifetime),
            expiresAt: lifetime === ROOM_CONSTANTS.ROOM_LIFETIMES.PERMANENT ? null : new Date(Date.now() + parseInt(lifetime)).toISOString(),
            category: category ? category.toLowerCase() : null
        };

        if (type === 'private') {
            if (!password || password.length < ROOM_CONSTANTS.MIN_PASSWORD_LENGTH) {
                return res.status(400).json({
                    error: `Password must be at least ${ROOM_CONSTANTS.MIN_PASSWORD_LENGTH} characters long`
                });
            }
            roomInfo.password = await encrypt(password);
        }

        await db.set(`rooms.${roomId}`, JSON.stringify(roomInfo));
        logger.info(`Room ${roomId} created with lifetime: ${lifetime}`);

        res.status(201).json({ roomId, roomName: sanitizedRoomName, expiresAt: roomInfo.expiresAt, category: roomInfo.category });
    } catch (error) {
        logger.error('Error creating room:', error);
        res.status(500).json({ error: 'Failed to create room' });
    }
}];

exports.joinRoom = [limiter, async (req, res) => {
    try {
        const { roomId, userId, password } = req.body;

        if (!roomId || !userId) {
            return res.status(400).json({ error: 'Room ID and user ID are required' });
        }

        const sanitizedUserId = sanitizeInput(userId);
        if (sanitizedUserId.toLowerCase() === "system") {
            return res.status(400).json({ error: "Username 'System' is not allowed" });
        }

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        if (room.users.length >= ROOM_CONSTANTS.MAX_USERS) {
            return res.status(403).json({ error: 'Room is full' });
        }

        if (room.users.includes(sanitizedUserId)) {
            return res.status(400).json({ error: 'Username already taken in this room' });
        }

        if (room.type === 'private') {
            if (!password) {
                return res.status(403).json({ error: 'Password required for private room' });
            }
            const decryptedPassword = await decrypt(room.password);
            if (password !== decryptedPassword) {
                return res.status(403).json({ error: 'Invalid password' });
            }
        }

        room.users.push(sanitizedUserId);
        room.lastActivity = new Date().toISOString();
        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        logger.info(`User ${sanitizedUserId} joined room ${roomId}`);
        res.status(200).json({ message: 'Joined room successfully' });
    } catch (error) {
        logger.error('Error joining room:', error);
        res.status(500).json({ error: 'Failed to join room' });
    }
}];

exports.sendMessage = [userLimiter, async (req, res) => {
    try {
        const { roomId, userId, message } = req.body;

        if (!roomId || !userId || !message) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const sanitizedUserId = sanitizeInput(userId);
        if (sanitizedUserId.toLowerCase() === "system") {
            return res.status(400).json({ error: "Username 'System' is not allowed" });
        }

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        if (!room.users.includes(sanitizedUserId)) {
            return res.status(403).json({ error: 'User not in room' });
        }

        const sanitizedMessage = sanitizeInput(message);
        const encryptedMessage = await encrypt(sanitizedMessage);
        const messageObj = {
            id: uuidv4(),
            userId: sanitizedUserId,
            message: encryptedMessage,
            timestamp: new Date().toISOString(),
            readBy: [sanitizedUserId],
            reactions: {}
        };

        room.messages.push(messageObj);
        room.lastActivity = new Date().toISOString();
        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        global.io.to(roomId).emit('newMessage', {
            id: messageObj.id,
            sender: sanitizedUserId,
            message: encryptedMessage,
            timestamp: messageObj.timestamp,
            readBy: messageObj.readBy,
            reactions: messageObj.reactions
        });

        if (room.users.length <= 1) {
            await db.delete(`rooms.${roomId}`);
            logger.info(`Room ${roomId} deleted due to inactivity`);
            return res.status(404).json({ error: 'Room has been deleted due to inactivity' });
        }

        return res.status(200).json({ message: 'Message sent successfully' });
    } catch (error) {
        logger.error('Error sending message:', error);
        return res.status(500).json({ error: 'Failed to send message' });
    }
}];

exports.getMessages = async (req, res) => {
    try {
        const { roomId } = req.params;
        const { limit = 50, before } = req.query;

        if (!roomId) {
            return res.status(400).json({ error: 'Room ID is required' });
        }

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);
        let messages = room.messages;

        if (before) {
            messages = messages.filter(msg => new Date(msg.timestamp) < new Date(before));
        }

        const limitNum = Math.min(parseInt(limit), 50);
        messages = messages.slice(-limitNum);

        const encryptedMessages = messages.map(message => ({
            id: message.id,
            userId: message.userId,
            message: message.message,
            timestamp: message.timestamp,
            readBy: message.readBy,
            reactions: message.reactions
        }));

        res.status(200).json({ messages: encryptedMessages });
    } catch (error) {
        logger.error('Error getting messages:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
};

exports.listAllRooms = async (req, res) => {
    try {
        const { type, minUsers, sort, page = 1, limit = 20, category } = req.query;

        const rooms = await db.all();

        let filteredRooms = rooms.map(room => {
            try {
                const roomData = JSON.parse(room.data);
                return {
                    id: room.ID.split('.')[1],
                    roomName: roomData.roomName,
                    type: roomData.type,
                    userCount: roomData.users.length,
                    messageCount: roomData.messages.length,
                    createdAt: roomData.createdAt || new Date().toISOString(),
                    lastActivity: roomData.lastActivity || roomData.createdAt || new Date().toISOString(),
                    isEmpty: roomData.users.length <= 1,
                    lifetime: roomData.lifetime || ROOM_CONSTANTS.ROOM_LIFETIMES.PERMANENT,
                    expiresAt: roomData.expiresAt || null,
                    isPermanent: roomData.lifetime === ROOM_CONSTANTS.ROOM_LIFETIMES.PERMANENT,
                    remainingTime: roomData.expiresAt ? Math.max(0, new Date(roomData.expiresAt).getTime() - Date.now()) : null,
                    owner: roomData.owner,
                    category: roomData.category
                };
            } catch (parseError) {
                logger.error(`Error parsing room data for room ID ${room.ID}:`, parseError);
                return null;
            }
        }).filter(room => room !== null);

        if (type && !['public', 'private'].includes(type)) {
            return res.status(400).json({ error: 'Invalid room type' });
        }

        if (type) {
            filteredRooms = filteredRooms.filter(room => room.type === type);
        }

        if (minUsers) {
            const validatedMinUsers = Math.max(1, parseInt(minUsers) || 1);
            filteredRooms = filteredRooms.filter(room => room.userCount >= validatedMinUsers);
        }

        if (category) {
            filteredRooms = filteredRooms.filter(room => room.category === category.toLowerCase());
        }

        const validSortOptions = ['users', 'messages', 'newest', 'activity'];
        if (sort && !validSortOptions.includes(sort)) {
            return res.status(400).json({ error: 'Invalid sort option' });
        }

        if (sort) {
            switch (sort) {
                case 'users':
                    filteredRooms.sort((a, b) => b.userCount - a.userCount);
                    break;
                case 'messages':
                    filteredRooms.sort((a, b) => b.messageCount - a.messageCount);
                    break;
                case 'newest':
                    filteredRooms.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                    break;
                case 'activity':
                    filteredRooms.sort((a, b) => new Date(b.lastActivity) - new Date(a.lastActivity));
                    break;
            }
        }

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(50, Math.max(1, parseInt(limit)));
        const startIndex = (pageNum - 1) * limitNum;
        const endIndex = startIndex + limitNum;
        const paginatedRooms = filteredRooms.slice(startIndex, endIndex);

        res.status(200).json({
            rooms: paginatedRooms,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total: filteredRooms.length,
                totalPages: Math.ceil(filteredRooms.length / limitNum)
            }
        });
    } catch (error) {
        logger.error('Error listing rooms:', error);
        res.status(500).json({ error: 'Failed to list rooms' });
    }
};

exports.checkRoom = async (req, res) => {
    try {
        const { roomId } = req.params;

        if (!roomId) {
            return res.status(400).json({ error: 'Room ID is required' });
        }

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        const safeRoom = {
            type: room.type,
            userCount: room.users.length,
            messageCount: room.messages.length,
            createdAt: room.createdAt,
            lastActivity: room.lastActivity,
            isEmpty: room.users.length <= 1,
            roomName: room.roomName,
            owner: room.owner,
            category: room.category
        };

        res.status(200).json({ room: safeRoom });
    } catch (error) {
        logger.error('Error checking room:', error);
        res.status(500).json({ error: 'Failed to check room' });
    }
};

exports.leaveRoom = async (req, res) => {
    try {
        const { roomId, userId } = req.body;

        if (!roomId || !userId) {
            return res.status(400).json({ error: 'Room ID and user ID are required' });
        }

        const sanitizedUserId = sanitizeInput(userId);
        const roomData = await db.get(`rooms.${roomId}`);

        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        if (!room.users.includes(sanitizedUserId)) {
            return res.status(400).json({ error: 'User not in room' });
        }

        room.users = room.users.filter(id => id !== sanitizedUserId);
        if (room.typingUsers) {
            room.typingUsers = room.typingUsers.filter(id => id !== sanitizedUserId);
        }
        room.lastActivity = new Date().toISOString();

        const systemMessage = {
            id: uuidv4(),
            userId: 'System',
            message: await encrypt(`${sanitizedUserId} left the room`),
            timestamp: new Date().toISOString(),
            type: 'system'
        };
        room.messages.push(systemMessage);

        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        global.io.to(roomId).emit('newMessage', {
            id: systemMessage.id,
            sender: 'System',
            message: systemMessage.message,
            timestamp: systemMessage.timestamp,
            type: 'system'
        });

        global.io.to(roomId).emit('typingStatus', {
            userId: sanitizedUserId,
            isTyping: false,
            typingUsers: room.typingUsers
        });

        logger.info(`User ${sanitizedUserId} left room ${roomId}`);
        res.status(200).json({ message: 'Left room successfully' });
    } catch (error) {
        logger.error('Error leaving room:', error);
        res.status(500).json({ error: 'Failed to leave room' });
    }
};

exports.markMessageAsRead = async (req, res) => {
    try {
        const { roomId, userId, messageId } = req.body;

        if (!roomId || !userId || !messageId) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const sanitizedUserId = sanitizeInput(userId);

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        if (!room.users.includes(sanitizedUserId)) {
            return res.status(403).json({ error: 'User not in room' });
        }

        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex === -1) {
            return res.status(404).json({ error: 'Message not found' });
        }

        if (!room.messages[messageIndex].readBy) {
            room.messages[messageIndex].readBy = [];
        }

        if (!room.messages[messageIndex].readBy.includes(sanitizedUserId)) {
            room.messages[messageIndex].readBy.push(sanitizedUserId);
            await db.set(`rooms.${roomId}`, JSON.stringify(room));

            global.io.to(roomId).emit('messageRead', {
                messageId,
                userId: sanitizedUserId,
                readBy: room.messages[messageIndex].readBy
            });
        }

        res.status(200).json({ message: 'Message marked as read' });
    } catch (error) {
        logger.error('Error marking message as read:', error);
        res.status(500).json({ error: 'Failed to mark message as read' });
    }
};

exports.reactToMessage = async (req, res) => {
    try {
        const { roomId, userId, messageId, emoji } = req.body;

        if (!roomId || !userId || !messageId || !emoji) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const sanitizedUserId = sanitizeInput(userId);
        const roomData = await db.get(`rooms.${roomId}`);

        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        if (!room.users.includes(sanitizedUserId)) {
            return res.status(403).json({ error: 'User not in room' });
        }

        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex === -1) {
            return res.status(404).json({ error: 'Message not found' });
        }

        if (!room.messages[messageIndex].reactions) {
            room.messages[messageIndex].reactions = {};
        }

        if (!room.messages[messageIndex].reactions[emoji]) {
            room.messages[messageIndex].reactions[emoji] = [];
        }

        const userReactionIndex = room.messages[messageIndex].reactions[emoji].indexOf(sanitizedUserId);
        let action;

        if (userReactionIndex === -1) {
            room.messages[messageIndex].reactions[emoji].push(sanitizedUserId);
            action = 'added';
        } else {
            room.messages[messageIndex].reactions[emoji].splice(userReactionIndex, 1);
            if (room.messages[messageIndex].reactions[emoji].length === 0) {
                delete room.messages[messageIndex].reactions[emoji];
            }
            action = 'removed';
        }

        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        global.io.to(roomId).emit('messageReaction', {
            messageId,
            userId: sanitizedUserId,
            emoji,
            action,
            reactions: room.messages[messageIndex].reactions
        });

        res.status(200).json({ message: `Reaction ${action}` });
    } catch (error) {
        logger.error('Error reacting to message:', error);
        res.status(500).json({ error: 'Failed to react to message' });
    }
};

exports.errorHandler = (err, req, res, next) => {
    logger.error('Unexpected error:', err);
    res.status(500).json({ error: 'An unexpected error occurred' });
};

exports.validateUser = (req, res, next) => {
    const userId = req.body.userId || req.query.userId;

    if (!userId || !ROOM_CONSTANTS.USERNAME_REGEX.test(userId)) {
        return res.status(400).json({ error: 'Invalid username format' });
    }

    if (ROOM_CONSTANTS.RESERVED_USERNAMES.includes(userId.toLowerCase())) {
        return res.status(400).json({ error: 'This username is not allowed' });
    }

    next();
};