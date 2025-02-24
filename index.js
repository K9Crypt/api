const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');
const { deleteMessages, scheduledTask } = require('./controllers/deleteMessages');
const roomRoutes = require('./routes/room');
const createRoutes = require('./routes/create');
const viewRoutes = require('./routes/view');
const socketService = require('./services/socketService');
const { initializeOfficialRoom } = require('./controllers/roomController');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

global.io = io;

const limiter = rateLimit({
    windowMs: 3 * 60 * 1000,
    max: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
});

app.set('trust proxy', 1);
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.status(200).send('K9Crypt API is live!');
});

app.use('/room', limiter, roomRoutes);
app.use('/create', limiter, createRoutes);
app.use('/view', limiter, viewRoutes);

socketService(io);

server.listen(1573, () => {
    console.log('K9Crypt API listening on port 1573!');
    initializeOfficialRoom();
    deleteMessages();
    scheduledTask.start();
});
