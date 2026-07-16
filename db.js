const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
const isLocal = /localhost|127\.0\.0\.1/.test(connectionString || '');

const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
});

function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query };
