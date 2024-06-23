const cron = require('node-cron');
const db = require('../database/db');

/**
 * Asynchronously deletes all messages from the database.
 * 
 * This function attempts to clear all messages stored in the database.
 * If the operation is successful, a success message is logged to the console.
 * If an error occurs during the operation, an error message is logged to the console.
 * 
 * @async
 * @function deleteMessages
 * @returns {Promise<void>} A promise that resolves when the messages are deleted.
 */
async function deleteMessages() {
    try {
        await db.clear();
        console.log('All messages deleted successfully.');
    } catch (error) {
        console.error('Error deleting messages:', error.message);
    }
}

const scheduledTask = cron.schedule('0 */2 * * *', deleteMessages);

module.exports = {
    deleteMessages,
    scheduledTask
};
