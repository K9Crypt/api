const validator = require('validator');

function validateRoomInput({ userId, type, password }) {
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
        return false;
    }

    if (type && !['public', 'private'].includes(type)) {
        return false;
    }

    if (type === 'private' && (!password || typeof password !== 'string' || password.length < 6)) {
        return false;
    }

    return true;
}

function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return '';
    }
    
    let sanitized = input.replace(/<[^>]*>/g, '');
    sanitized = validator.escape(sanitized);
    sanitized = sanitized.trim();
    
    return sanitized;
}

module.exports = {
    validateRoomInput,
    sanitizeInput
};