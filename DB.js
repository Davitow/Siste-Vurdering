const sqlite3 = require("sqlite3").verbose(); // Importerer SQLite-modulen med ekstra logging //

// Åpner tilkobling til databasen 'users.db' //
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Feil ved tilkobling til SQLite:", err.message); // Feilmelding om det er en error ved tilkobling til database //
  } else {
    console.log("Tilkoblet til SQLite-databasen."); // else-statement som forklarer at tilkoblingen til databasen var vellykket //
  }
});

// Lager tabeller hvis de ikke finnes fra før av //
db.serialize(() => {
  // Lager tabell for brukere //
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Lager tabell for innlegg //
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Lager tabell for kommentarer //
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER,
      user_id INTEGER,
      comment TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

module.exports = db; // Gjør databasen tilgjengelig for andre filer //