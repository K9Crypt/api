const express = require('express');
const k9crypt = require('k9crypt');
const router = express.Router();

router.post('/', async (req, res) => {
    const { message } = req.body;
    const secretKey = process.env.SECRET_KEY || "defaultSecretKey";
    const encryptor = new k9crypt(secretKey);
    const decrypted = await encryptor.decrypt(message);
    res.status(200).send(decrypted);
});

module.exports = router;