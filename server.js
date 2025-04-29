require("dotenv").config(); // Laster miljøvariabler fra .env fil //
const express = require("express"); // Importerer express-rammeverk //
const bcrypt = require("bcrypt"); // Importerer bcrypt for hashing av passord //
const bodyParser = require("body-parser"); // Importerer body-parser for å lese POST data //
const session = require("express-session"); // Importerer sessions for innlogging //
const db = require("./DB"); // Importer SQLite-tilkoblingen

const app = express(); // oppretter express app //
const PORT = 3000; // definerer PORT til 3000: PORT 3000 //

// Middleware //
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

      // Sett inn brukeren i databasen //
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

// 📌 Håndter innlogging (verifiserer bruker fra SQLite) //
app.post("/login", (req, res) => {
  const { username, password } = req.body;

// Henter bruker fra databasen //
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) {
      return res.render("login", { message: "Brukeren finnes ikke!" });
    }

    const match = await bcrypt.compare(password, user.password); // Sammenligner skrevet passord på login side med hashet passord i databasen //

    if (match) {
      req.session.user = { id: user.id, username: user.username }; // Om passord stemmer lagres bruker data i økten //
    
      // Henter brukers innlegg sortert etter nyeste først //
      db.all(` 
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
      `, [], (err, posts) => {
        if (err) {
          console.error(err);
          return res.send("Feil ved lasting av innlegg."); // Sender error melding om det er feil ved lasting av innlegg //
        }
    
        const postsWithComments = [];
        let count = 0;
    
        // Henter kommentarer tilhørerende innlegg med forfatters brukernavn//
        posts.forEach((post) => {
          db.all(`
            SELECT comments.*, users.username 
            FROM comments 
            JOIN users ON comments.user_id = users.id
            WHERE comments.post_id = ?
            ORDER BY comments.created_at ASC
          `, [post.id], (err, comments) => {
            if (err) {
              console.error(err);
              return res.send("Feil ved lasting av kommentarer."); // sender error melding om det er feil ved lasting av kommentarer //
            }
    
            postsWithComments.push({ ...post, comments });
            count++;
    
            if (count === posts.length) {
              res.render("welcome", { username: user.username, posts: postsWithComments });
            }
          });
        });
    
        if (posts.length === 0) {
          res.render("welcome", { username: user.username, posts: [] });
        }
      });
    } else {
      res.render("login", { message: "Feil passord!" });
    }
  });
});

// Logg ut //
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Håndter sletting av konto //
app.post("/delete-account", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  //redirect til en side som håndterer bekreftelse fra bruker om sletting av konto//
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

// Lager POST-rute for å bekrefte sletting av konto //
app.post("/confirm-delete", (req, res) => {
  // Sjekker om brukeren er logget inn, ellers om de ikke er logget inn blir de redirectet til forsiden //
  if (!req.session.user) {
    return res.redirect("/");
  }

  const userId = req.session.user.id;
  const { password } = req.body;

  // Henter bruker fra databasen //
  db.get("SELECT * FROM users WHERE id = ?", [userId], async (err, user) => {
    if (err || !user) {
      return res.send("Feil ved henting av bruker.");
    }

    // Sjekker om passordet er korrekt //
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send("Feil passord! Kontoen ble ikke slettet.");
    }

    // Slett brukeren fra databasen //
    db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
      if (err) {
        console.error("Feil ved sletting av konto:", err.message);
        return res.send("Feil ved sletting av konto.");
      }

      req.session.destroy(() => {
        res.send("<h2>Kontoen din er slettet.</h2><a href='/'>Gå til forsiden</a>"); // Sender melding på siden om at kontoen har blitt slettet //
      });
    });
  });
});

// Starter serveren //
app.listen(PORT, () => {
  console.log(`Server kjører på http://localhost:${PORT}`);
});

app.get("/Welcome", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
});

//  Viser alle innlegg //
app.get("/posts", (req, res) => {
  // Sjekker om bruker er logget inn, ellers redirecter til forsiden //
  if (!req.session.user) {
    return res.redirect("/");
  }

  // Henert alle innlegg med tilhørende brukernavn, sortert etter nyeste først //
  db.all(`
    SELECT posts.*, users.username 
    FROM posts 
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  `, [], (err, posts) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved lasting av innlegg."); // Error melding ved feil av lasting av innlegg //
    }

    const postsWithComments = [];
    let count = 0;

    // For hvert innlegg, henter tilhørende kommentarer med brukernavn //
    posts.forEach((post) => {
      db.all(`
        SELECT comments.*, users.username 
        FROM comments 
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.created_at ASC
      `, [post.id], (err, comments) => {
        if (err) {
          console.error(err);
          return res.send("Feil ved lasting av kommentarer."); // Error melding ved feil av lasting av innlegg //
        }

        // Legg innlegget og dets kommentarer til resultatlista
        postsWithComments.push({ ...post, comments });
        count++;

        // Når alle innlegg er behandlet, rendres siden med dataene
        if (count === posts.length) {
          res.render("posts", { username: req.session.user.username, posts: postsWithComments });
        }
      });
    });
  });
});

//  Lager POST-rute for å legge til nytt innlegg //
app.post("/posts", (req, res) => {
  // Sjekker om bruker er logget inn //
  if (!req.session.user) {
    return res.redirect("/");
  }

  // Henter tittel og innhold fra skjemaet, og bruker-ID fra sesjonen //
  const { title, content } = req.body;
  const userId = req.session.user.id;

  // Setter inn nytt innlegg i databasen //
  db.run("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)", [userId, title, content], (err) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved publisering av innlegg.");
    }
    // Går tilbake til innleggssiden etter lagring //
    res.redirect("/posts");
  });
});

app.post("/comments/:postId", (req, res) => {
  // Sjekker om bruker er logget inn //
  if (!req.session.user) {
    return res.redirect("/");
  }

  // Henter kommentartekst fra skjemaet //
  const { comment } = req.body;

  // Henter ID til innlegget fra URL //
  const postId = req.params.postId;

  // Henter brukerens ID fra sesjonen //
  const userId = req.session.user.id;

  // Sett inn kommentaren i databasen
  db.run("INSERT INTO comments (post_id, user_id, comment) VALUES (?, ?, ?)", [postId, userId, comment], (err) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved publisering av kommentar."); // Sender en error meldingen om det blir feil ved publisering av kommentarer //
    }
    // Gå tilbake til innleggssiden etter lagring //
    res.redirect("/posts");
  });
});

// Viser redigeringsskjema for brukerkonto //
app.get("/edit-account", (req, res) => {
  // Sjekk om bruker er logget inn
  if (!req.session.user) {
    return res.redirect("/");
  }

  // Viser skjema med nåværende brukernavn //
  res.render("edit-account", { username: req.session.user.username });
});

// Lager POST-rute som håndter oppdatering av brukerkonto //
app.post("/update-account", async (req, res) => {
  // Sjekk om bruker er logget inn
  if (!req.session.user) {
    return res.redirect("/");
  }

  const userId = req.session.user.id; // Henter brukerens ID fra innlogget sesjon //
  const { newUsername, newPassword } = req.body; // Henter nytt brukernavn og passord fra innsendt skjema //
  const saltRounds = 12; // Antall runder med salting som brukes ved hashing av passord //

  try {
    // Krypter det nye passordet
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Oppdater brukernavn og passord i databasen
    db.run(
      "UPDATE users SET username = ?, password = ? WHERE id = ?",
      [newUsername, hashedPassword, userId],
      function (err) {
        if (err) {
          console.error(err.message);
          return res.send("Feil ved oppdatering av konto."); // Sender error melding om det blir en feil ved oppdatering av konto //
        }

        // Oppdater sesjonsdata med nytt brukernavn
        req.session.user.username = newUsername;

        // Send bruker tilbake til velkomstsiden
        res.redirect("/Welcome");
      }
    );
  } catch (error) {
    // Håndter eventuelle feil ved hashing
    console.error(error);
    res.send("Feil ved oppdatering av konto.");
  }
});