const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors');
const { deleteMessages, scheduledTask } = require('./controllers/deleteMessages');
const create = require('./routes/create');
const view = require('./routes/view');
const { rateLimit } = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 3 * 60 * 1000,
    max: 300,
    standardHeaders: 'draft-7',
	legacyHeaders: false,
});

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.status(200).send('K9Crypt API is live!');
});

app.use('/create', limiter, create);
app.use('/view', limiter, view);

app.listen(3000, () => {
    console.log('K9Crypt API listening on port 3000!');
    deleteMessages();
    scheduledTask.start();
});