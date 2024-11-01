require('dotenv').config();
const { Database } = require('st.db');
const { MongoDriver } = require('@st.db/mongodb');
const options = {
    driver: new MongoDriver(process.env.DATABASE_URL, "k9crypt", "messages"),
};

const db = new Database(options);

module.exports = db;