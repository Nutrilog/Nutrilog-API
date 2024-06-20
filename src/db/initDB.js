const { getConnection } = require("./index");


const userTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) NOT NULL DEFAULT (CONCAT('USR_', UUID())) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    gender ENUM('male', 'female') NOT NULL,
    date_of_birth DATE NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  );
`;

const nutritionTableQuery = `
  CREATE TABLE IF NOT EXISTS nutrients (
    id VARCHAR(255) NOT NULL DEFAULT (CONCAT('NU_', UUID())) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    food_name VARCHAR(255) NOT NULL,
    calories FLOAT NOT NULL,
    proteins FLOAT NOT NULL,
    carbohydrate FLOAT NOT NULL,
    fat FLOAT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`;


const createTables = async () => {
  const db = await getConnection();
  try {
    await db.query(userTableQuery);
    await db.query(nutritionTableQuery);
  } catch (err) {
    console.error('Error during createTables:', err);
  } finally {
    await db.end();
  }
}

createTables();
