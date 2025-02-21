const { encrypt, decrypt } = require('../utils/encryption');
const db = require('../database/db');

module.exports = (io) => {
    io.on('connection', (socket) => {
        console.log('New client connected');

        socket.on('joinRoom', async ({ roomId, userId }) => {
            socket.join(roomId);
            console.log(`User ${userId} joined room ${roomId}`);
        });

        socket.on('sendMessage', async ({ roomId, userId, message }) => {
            const roomData = await db.get(`rooms.${roomId}`);
            if (roomData) {
                const room = JSON.parse(roomData);
                if (room.users.includes(userId)) {
                    const encryptedMessage = await encrypt(message);
                    room.messages.push({ userId, message: encryptedMessage });
                    await db.set(`rooms.${roomId}`, JSON.stringify(room));
                    io.to(roomId).emit('newMessage', { userId, message: encryptedMessage });
                }
            }
        });

        socket.on('disconnect', () => {
            console.log('Client disconnected');
        });
    });
};