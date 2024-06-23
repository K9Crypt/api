require('dotenv').config();
const db = require('../database/db');
const AES = require('crypto-js/aes');
const Utf8 = require('crypto-js/enc-utf8');

/**
 * Handles the viewing of a message by its code.
 * 
 * @param {Object} req - The request object.
 * @param {Object} req.params - The parameters from the request.
 * @param {string} req.params.code - The code used to retrieve the message.
 * @param {Object} res - The response object.
 * 
 * @returns {Promise<void>} - Sends the decrypted message or an error response.
 */
async function view(req, res) {
    const { code } = req.params;

    try {
        const encryptedMessage = await db.get(code);

        if (!encryptedMessage) {
            return res.status(404).send('Message not found');
        }

        const secretKey = process.env.SECRET_KEY || 'default-secret-key';
        const decryptedMessage = AES.decrypt(encryptedMessage, secretKey).toString(Utf8);

        res.status(200).send(decryptedMessage);
    } catch (error) {
        console.error(`Error fetching or decrypting message: ${error.message}`);
        res.status(500).send('Internal Server Error');
    }
}

module.exports = view;
