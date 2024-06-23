const view = require('../controllers/view');
const express = require('express');
const router = express.Router();

router.get('/:code', view);

module.exports = router;