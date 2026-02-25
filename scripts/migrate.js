const fs = require("fs");
const path = require("path");
const pool = require("../db");

(async () => {
  try {
    const sql = fs.readFileSync(path.join(__dirname, "..", "schema.sql"), "utf8");
    await pool.query(sql);
    console.log("✅ Database schema ensured.");
    process.exit(0);
  } catch (err) {
    console.error("Migration Failed:", err);
    process.exit(1);
  }
})();
