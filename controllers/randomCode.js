/**
 * Generates a random alphanumeric code of length 6.
 *
 * The code consists of lowercase letters, uppercase letters, and digits.
 *
 * @returns {string} A random alphanumeric code.
 */
function generateRandomCode() {
    let characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let randomCode = '';
    for (let i = 0; i < 6; i++) {
        randomCode += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return randomCode;
}

module.exports = generateRandomCode;