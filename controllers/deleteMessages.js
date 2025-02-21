const cron = require('node-cron');
const db = require('../database/db');
const logger = require('../utils/logger');

async function deleteMessages() {
    try {
        const rooms = await db.all();
        if (!rooms) {
          logger.info("No rooms found. Skipping message deletion.");
          return;
        }

        const now = new Date().getTime();
        let deletedMessageCount = 0;

        for (const room of rooms) {
            try {
                if (!room || !room.data || !room.ID) {
                    logger.warn(`Skipping invalid room entry: ${JSON.stringify(room)}`);
                    continue;
                }

                let roomData;
                try {
                    roomData = JSON.parse(room.data);
                } catch (parseError) {
                    logger.error(`Error parsing room data for room ID ${room.ID}:`, parseError);
                    continue;
                }

                const expiresAt = roomData.expiresAt ? new Date(roomData.expiresAt).getTime() : null;

                if (expiresAt !== null && now > expiresAt) {
                    await db.delete(room.ID);
                    deletedMessageCount++;
                    logger.info(`Room and messages deleted (ID: ${room.ID}) - Room expired`);
                }
            } catch (innerError) {
                logger.error(`Error processing room ID ${room.ID}:`, innerError);
            }
        }

        if (deletedMessageCount > 0) {
            logger.info(`Message cleanup completed: ${deletedMessageCount} rooms and their messages deleted`);
        } else {
            logger.info("Message cleanup completed: No rooms were deleted.");
        }
    } catch (outerError) {
        logger.error('Error deleting expired messages (outer catch):', outerError);
    }
}

const scheduledTask = cron.schedule('0 * * * *', deleteMessages);

module.exports = {
    deleteMessages,
    scheduledTask
};