const cron = require('node-cron');
const db = require('../database/db');

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