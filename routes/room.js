const express = require('express');
const router = express.Router();
const { createRoom, joinRoom, leaveRoom, sendMessage, getMessages, checkRoom, listAllRooms, markMessageAsRead, reactToMessage } = require('../controllers/roomController');

router.post('/create', createRoom);
router.post('/join', joinRoom);
router.post('/leave', leaveRoom);
router.post('/message', sendMessage);
router.get('/:roomId/messages', getMessages);
router.get('/check/:roomId', checkRoom);
router.get('/list', listAllRooms);
router.post('/read', markMessageAsRead);
router.post('/react', reactToMessage);

module.exports = router;