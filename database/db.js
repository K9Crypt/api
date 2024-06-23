require('dotenv').config();
const { Database, MongoDriver } = require('st.db');
const data = {
    url: process.env.DATABASE_URL,
    dbName: "k9crypt",
    collectionName: "messages"
}
const options = {
    driver: new MongoDriver(data.url, data.dbName, data.collectionName),
}
const db = new Database(options);

module.exports = db;
