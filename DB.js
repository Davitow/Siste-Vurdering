const sqlite3 = require("sqlite3").verbose();

// Opprett en databasefil (hvis den ikke finnes)
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Feil ved tilkobling til SQLite:", err.message);
  } else {
    console.log("Tilkoblet til SQLite-databasen.");
  }
});

// Opprett en tabell for brukere (hvis den ikke finnes)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
});

module.exports = db;
