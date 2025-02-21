const express = require('express');
const k9crypt = require('k9crypt');
const xss = require('xss');
const router = express.Router();

router.post('/', async (req, res) => {
    try {
        const { message } = req.body;
        const secretKey = process.env.SECRET_KEY || "defaultSecretKey";
        const encryptor = new k9crypt(secretKey);
        const decrypted = await encryptor.decrypt(message);

        const sanitizedData = xss(decrypted);

        res.status(200).send(sanitizedData);
    } catch (error) {
        res.status(500).send('Bir hata oluştu');
    }
});

module.exports = router;