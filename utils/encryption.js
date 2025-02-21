const k9crypt = require('k9crypt');
const secretKey = process.env.SECRET_KEY || "defaultSecretKey";
const encryptor = new k9crypt(secretKey);

exports.encrypt = async (data) => {
    return await encryptor.encrypt(data);
};

exports.decrypt = async (data) => {
    return await encryptor.decrypt(data);
};