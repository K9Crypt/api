require('dotenv').config();
const AES = require('crypto-js/aes');
const randomCode = require('./randomCode');
const db = require('../database/db');

/**
 * Asynchronous function to create and save an encrypted message.
 *
 * @param {Object} req - The request object containing the message in the body.
 * @param {Object} res - The response object used to send back the appropriate HTTP response.
 *
 * @returns {Promise<void>} - A promise that resolves to void.
 */
async function create(req, res) {
    const { message } = req.body;

    if (!message) {
        return res.status(400).send('Message is required');
    }

    const secretKey = process.env.SECRET_KEY || 'default-secret-key';
    const encryptedMessage = AES.encrypt(message, secretKey).toString();
    const code = randomCode();

    try {
        await db.set(code, encryptedMessage);
        res.status(201).send(`${code}`);
    } catch (error) {
        console.error('Error saving message:', error.message);
        res.status(500).send('Error saving message.');
    }
}

module.exports = create;
