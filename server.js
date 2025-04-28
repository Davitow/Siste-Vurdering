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
    
      db.all(`
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
      `, [], (err, posts) => {
        if (err) {
          console.error(err);
          return res.send("Feil ved lasting av innlegg.");
        }
    
        const postsWithComments = [];
        let count = 0;
    
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
              return res.send("Feil ved lasting av kommentarer.");
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

// 📌 Logg ut
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// 📌 Håndter sletting av konto
app.post("/delete-account", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
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

app.get("/Welcome", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  db.all(`
    SELECT posts.*, users.username 
    FROM posts 
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  `, [], (err, posts) => {
    if (err) {
      console.error(err);
      return res.render("welcome", { username: req.session.user.username, posts: [] });
    }

    if (!posts || posts.length === 0) {
      return res.render("welcome", { username: req.session.user.username, posts: [] });
    }

    const postsWithComments = [];
    let count = 0;

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
          return res.send("Feil ved lasting av kommentarer.");
        }

        postsWithComments.push({ ...post, comments });
        count++;

        if (count === posts.length) {
          // Når ALLE innleggene og kommentarene er ferdig lastet
          res.render("welcome", { username: req.session.user.username, posts: postsWithComments });
        }
      });
    });
  });
});

// 📌 Vis alle innlegg
app.get("/posts", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  db.all(`
    SELECT posts.*, users.username 
    FROM posts 
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  `, [], (err, posts) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved lasting av innlegg.");
    }

    const postsWithComments = [];
    let count = 0;

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
          return res.send("Feil ved lasting av kommentarer.");
        }

        postsWithComments.push({ ...post, comments });
        count++;

        if (count === posts.length) {
          res.render("posts", { username: req.session.user.username, posts: postsWithComments });
        }
      });
    });
  });
});

// 📌 Lag nytt innlegg
app.post("/posts", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const { title, content } = req.body;
  const userId = req.session.user.id;

  db.run("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)", [userId, title, content], (err) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved publisering av innlegg.");
    }
    res.redirect("/posts");
  });
});

// 📌 Kommenter et innlegg
app.post("/comments/:postId", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const { comment } = req.body;
  const postId = req.params.postId;
  const userId = req.session.user.id;

  db.run("INSERT INTO comments (post_id, user_id, comment) VALUES (?, ?, ?)", [postId, userId, comment], (err) => {
    if (err) {
      console.error(err);
      return res.send("Feil ved publisering av kommentar.");
    }
    res.redirect("/posts");
  });
});