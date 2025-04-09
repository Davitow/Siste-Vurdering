require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const session = require("express-session");
const db = require("./DB"); // Importer SQLite-tilkoblingen

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "hemmelignøkkel",
    resave: false,
    saveUninitialized: true,
  })
);

// 📌 Rute: Hovedside (Login)
app.get("/", (req, res) => {
  res.render("login", { message: "" });
});

// 📌 Rute: Registrering
app.get("/register", (req, res) => {
  res.render("register");
});

// 📌 Håndter registrering (lagrer bruker i SQLite)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 12;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Sjekk om brukeren allerede finnes
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (user) {
        return res.render("register", { message: "Brukernavnet er allerede tatt!" });
      }

      // Sett inn brukeren i databasen
      db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
        if (err) {
          console.error("Feil ved registrering:", err.message);
          return res.send("Feil ved registrering.");
        }
        res.redirect("/");
      });
    });
  } catch (err) {
    console.error(err);
    res.send("Feil ved registrering.");
  }
});

// 📌 Håndter innlogging (verifiserer bruker fra SQLite)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) {
      return res.render("login", { message: "Brukeren finnes ikke!" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      req.session.user = { id: user.id, username: user.username };
      res.render("welcome", { username: user.username }); // Endret til EJS-malen
    } else {
      res.render("login", { message: "Feil passord!" });
    }
  });
});

// 📌 Logg ut
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// 📌 Håndter sletting av konto
app.post("/delete-account", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/"); // Brukeren må logge inn
  }

  res.send(`
    <h2>Bekreft sletting av konto</h2>
    <form action="/confirm-delete" method="POST">
        <input type="password" name="password" placeholder="Skriv inn passordet ditt" required>
        <button type="submit">Bekreft sletting</button>
    </form>
    <br>
    <a href="/">Avbryt</a>
  `);
});

app.post("/confirm-delete", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const userId = req.session.user.id;
  const { password } = req.body;

  // Hent bruker fra databasen
  db.get("SELECT * FROM users WHERE id = ?", [userId], async (err, user) => {
    if (err || !user) {
      return res.send("Feil ved henting av bruker.");
    }

    // Sjekk om passordet er korrekt
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send("Feil passord! Kontoen ble ikke slettet.");
    }

    // Slett brukeren fra databasen
    db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
      if (err) {
        console.error("Feil ved sletting av konto:", err.message);
        return res.send("Feil ved sletting av konto.");
      }

      req.session.destroy(() => {
        res.send("<h2>Kontoen din er slettet.</h2><a href='/'>Gå til forsiden</a>");
      });
    });
  });
});

// Start serveren
app.listen(PORT, () => {
  console.log(`Server kjører på http://localhost:${PORT}`);
});