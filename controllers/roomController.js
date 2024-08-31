const { v4: uuidv4 } = require('uuid');
const db = require('../database/db');
const { encrypt, decrypt } = require('../utils/encryption');

/**
 * Generates a random room code consisting of uppercase letters, digits, and a length of 20.
 *
 * @return {string} The randomly generated room code.
 */
async function generateRoomCode() {
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
}

/**
 * Checks roomId's existence.
 *
 * @param {string} roomId
 * @returns {boolean}
 */
async function isRoomExists(roomId) {
    const result = await db.get(`rooms.${roomId}`);
    return !!result;
}

/**
 * Creates a new room.
 *
 * @param {Object} req - The request object containing the room code, user ID, and password (if applicable).
 * @param {Object} res - The response object used to send the result of the room creation operation.
 * @return {Promise<void>} - Resolves with a JSON response indicating the success of the room creation operation.
 */
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


/**
 * Joins a room.
 *
 * @param {Object} req - The request object containing the room ID, user ID, and password (if applicable).
 * @param {Object} res - The response object used to send the result of the join operation.
 * @return {Promise<void>} - Resolves with a JSON response indicating the success of the join operation.
 */
exports.joinRoom = async (req, res) => {
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
};

/**
 * Checks if a room exists.
 *
 * @param {Object} req - The request object containing the room ID.
 * @param {Object} res - The response object used to send the result of the room check operation.
 * @return {Promise<void>} - Resolves with a JSON response indicating the success of the room check operation.
 */
 exports.checkRoom = async (req, res) => {
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
 };

/**
 * Leaves a room.
 *
 * @param {Object} req - The request object containing the room ID and user ID.
 * @param {Object} res - The response object used to send the result of the leave operation.
 * @return {Promise<void>} - Resolves with a JSON response indicating the success of the leave operation.
 */
exports.leaveRoom = async (req, res) => {
    const { roomId, userId } = req.body;

    const roomData = await db.get(`rooms.${roomId}`);
    if (!roomData) {
        return res.status(404).json({ error: 'Room not found' });
    }

    const room = JSON.parse(roomData);
    room.users = room.users.filter(id => id !== userId);
    await db.set(`rooms.${roomId}`, JSON.stringify(room));

    res.status(200).json({ message: 'Left room successfully' });
};

/**
 * Sends a message to a room.
 *
 * @param {Object} req - The request object containing the room ID, user ID, and message.
 * @param {Object} res - The response object used to send the result of the message sending operation.
 * @return {Promise<void>} - Resolves with a JSON response indicating the success of the message sending operation.
 */
exports.sendMessage = async (req, res) => {
    const { roomId, userId, message } = req.body;

    if (userId.toLowerCase() === "System") {
        return res.status(400).json({ error: "Username 'System' is not allowed" });
    }

    try {
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
        console.error('Message sending failed', error);
        return res.status(500).json({ error: 'Message sending failed' });
    }
};

/**
 * Gets all messages in a room.
 *
 * @param {Object} req - The request object containing the room ID.
 * @param {Object} res - The response object used to send the result of the message fetching operation.
 * @return {Promise<void>} - Resolves with a JSON response containing the messages in the room.
 */
exports.getMessages = async (req, res) => {
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
};
