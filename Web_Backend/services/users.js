const db = require("../db");

async function getUserByUsername(username) {
  const result = await db.query("SELECT * FROM users WHERE username = ?", [username]);
  return result.rows[0];
}

module.exports = {
  getUserByUsername
};
