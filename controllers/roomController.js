const { v4: uuidv4 } = require('uuid');
const db = require('../database/db');
const { encrypt, decrypt } = require('../utils/encryption');

async function generateRoomCode() {
    try {
        let roomCode;
        let roomExists;
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        do {
            roomCode = '';

            for (let i = 0; i < 20; i++) {
                roomCode += characters.charAt(Math.floor(Math.random() * characters.length));
            }

            roomExists = await isRoomExists(roomCode);
        } while (roomExists);

        return roomCode;
    } catch (error) {
        throw error;
    }
}

async function isRoomExists(roomId) {
    try {
        const result = await db.get(`rooms.${roomId}`);
        return !!result;
    } catch (error) {
        throw error;
    }
}

exports.createRoom = async (req, res) => {
    try {
        const roomId = await generateRoomCode();
        const { userId, type, password } = req.body;

        if (userId.toLowerCase() === "system") {
            return res.status(400).json({ error: "Username 'System' is not allowed" });
        }

        const roomInfo = {
            users: [userId, "System"],
            messages: [],
            type: type || 'public'
        };

        if (type === 'private') {
            if (!password) {
                return res.status(400).json({ error: 'Password is required for private rooms' });
            }
            roomInfo.password = await encrypt(password);
        }

        await db.set(`rooms.${roomId}`, JSON.stringify(roomInfo));

        res.status(201).json({ roomId: roomId });
    } catch (error) {
        res.status(500).json({ error: "Room creation failed" });
    }
};

exports.joinRoom = async (req, res) => {
    try {
        const { roomId, userId, password } = req.body;

        if (userId.toLowerCase() === "System") {
            return res.status(400).json({ error: "Username 'System' is not allowed" });
        }

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);
        if (room.users.includes(userId)) {
            return res.status(200).json({ message: 'User already in room' });
        }

        if (room.type === 'private') {
            const decryptedPassword = await decrypt(room.password);
            if (password !== decryptedPassword) {
                return res.status(403).json({ error: 'Invalid password' });
            }
        }

        room.users.push(userId);
        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        res.status(200).json({ message: 'Joined room successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to join room' });
    }
};

exports.checkRoom = async (req, res) => {
    try {
        const { roomId } = req.params;
        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);
        if (room.password) {
            delete room.password;
        }
        res.status(200).json({ room });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check room' });
    }
};

exports.leaveRoom = async (req, res) => {
    try {
        const { roomId, userId } = req.body;

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);
        room.users = room.users.filter(id => id !== userId);
        await db.set(`rooms.${roomId}`, JSON.stringify(room));

        res.status(200).json({ message: 'Left room successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to leave room' });
    }
};

exports.sendMessage = async (req, res) => {
    try {
        const { roomId, userId, message } = req.body;

        if (userId.toLowerCase() === "System") {
            return res.status(400).json({ error: "Username 'System' is not allowed" });
        }

        const roomData = await db.get(`rooms.${roomId}`);

        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);
        if (!room.users.includes(userId)) {
            return res.status(403).json({ error: 'User not in room' });
        }

        const encryptedMessage = await encrypt(message);
        room.messages.push({ userId, message: encryptedMessage });
        await db.set(`rooms.${roomId}`, JSON.stringify(room));
        global.io.to(roomId).emit('newMessage', { sender: userId, message: encryptedMessage });
        return res.status(200).json({ message: 'Message sent successfully' });
    } catch (error) {
        return res.status(500).json({ error: 'Message sending failed' });
    }
};

exports.getMessages = async (req, res) => {
    try {
        const { roomId } = req.params;

        const roomData = await db.get(`rooms.${roomId}`);
        if (!roomData) {
            return res.status(404).json({ error: 'Room not found' });
        }

        const room = JSON.parse(roomData);

        const messages = await Promise.all(
            room.messages.map(async message => ({
                userId: message.userId,
                message: await decrypt(message.message)
            }))
        );

        res.status(200).json({ messages });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get messages' });
    }
};

exports.listAllRooms = async (req, res) => {
    try {
        const { type, minUsers, sort } = req.query;
        
        const rooms = await db.all();
        
        let filteredRooms = rooms.map(room => {
            const roomData = JSON.parse(room.data);
            return {
                ID: room.ID.split('.')[1],
                type: roomData.type,
                userCount: roomData.users.length,
                messageCount: roomData.messages.length,
                createdAt: roomData.createdAt || new Date().toISOString(),
                lastActivity: roomData.lastActivity || roomData.createdAt || new Date().toISOString(),
                isEmpty: roomData.users.length <= 1
            };
        });

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

        res.status(200).json({ rooms: filteredRooms });
    } catch (error) {
        res.status(500).json({ error: 'Failed to list rooms. Please try again later.' });
    }
};