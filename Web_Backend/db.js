const mysql = require("mysql2/promise");
const config = require("./config");

const pool = mysql.createPool({
  host: config.dbHost,
  port: config.dbPort,
  database: config.dbName,
  user: config.dbUser,
  password: config.dbPassword,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function query(text, params) {
  const [rows] = await pool.query(text, params);
  if (Array.isArray(rows)) {
    return { rows };
  }
  return {
    rows: [],
    insertId: rows.insertId,
    affectedRows: rows.affectedRows
  };
}

module.exports = {
  query,
  pool
};
