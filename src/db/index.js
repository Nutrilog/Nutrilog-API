const mysql = require('mysql2/promise');
require('dotenv').config();


const dbConfig = {
    host: '34.42.151.96',
    user: 'root',
    password: 'capstonenutrilog',
    database: 'dbnutrilog',
    timezone: 'Z'
};

let connection;

const getConnection = async () => {
    if (!connection) {
        connection = await mysql.createConnection(dbConfig);
    }
    return connection;
};

module.exports = {
    getConnection
};
