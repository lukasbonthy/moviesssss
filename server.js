// server.js
require("dotenv").config();

const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");    
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;
const TMDB_API_KEY = process.env.TMDB_API_KEY || "YOUR_TMDB_API_KEY_HERE";

// ---------- DB SETUP ----------
const db = new sqlite3.Database(path.join(__dirname, "app.db"));

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  );
});

// ---------- APP SETUP ----------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-darkflix",
    resave: false,
    saveUninitialized: false,
  })
);

// Inject currentUser + tmdbApiKey into all views
app.use((req, res, next) => {
  res.locals.tmdbApiKey = TMDB_API_KEY;
  if (!req.session.userId) {
    res.locals.currentUser = null;
    return next();
  }
  db.get(
    "SELECT id, name, email, bio, created_at FROM users WHERE id = ?",
    [req.session.userId],
    (err, user) => {
      if (err) return next(err);
      res.locals.currentUser = user || null;
      next();
    }
  );
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

// ---------- AUTH ROUTES ----------

// GET /signup
app.get("/signup", (req, res) => {
  res.render("signup", {
    error: null,
    values: {},
  });
});

// POST /signup
app.post("/signup", (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (!name || !email || !password || !confirmPassword) {
    return res.render("signup", {
      error: "Please fill in all fields.",
      values: { name, email },
    });
  }
  if (password !== confirmPassword) {
    return res.render("signup", {
      error: "Passwords do not match.",
      values: { name, email },
    });
  }

  db.get("SELECT id FROM users WHERE email = ?", [email], (err, existing) => {
    if (err) {
      console.error(err);
      return res.render("signup", {
        error: "Something went wrong. Please try again.",
        values: { name, email },
      });
    }
    if (existing) {
      return res.render("signup", {
        error: "An account with that email already exists.",
        values: { name, email },
      });
    }

    const hash = bcrypt.hashSync(password, 10);
    db.run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, hash],
      function (err2) {
        if (err2) {
          console.error(err2);
          return res.render("signup", {
            error: "Could not create account.",
            values: { name, email },
          });
        }
        // Auto-login
        req.session.userId = this.lastID;
        res.redirect("/movies");
      }
    );
  });
});

// GET /login
app.get("/login", (req, res) => {
  res.render("login", {
    error: null,
    values: {},
  });
});

// POST /login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render("login", {
      error: "Please enter email and password.",
      values: { email },
    });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error(err);
      return res.render("login", {
        error: "Something went wrong.",
        values: { email },
      });
    }
    if (!user) {
      return res.render("login", {
        error: "Invalid email or password.",
        values: { email },
      });
    }

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) {
      return res.render("login", {
        error: "Invalid email or password.",
        values: { email },
      });
    }

    req.session.userId = user.id;
    res.redirect("/movies");
  });
});

// POST /logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// ---------- ACCOUNT ----------
app.get("/profile", requireLogin, (req, res, next) => {
  db.get(
    "SELECT id, name, email, bio, created_at FROM users WHERE id = ?",
    [req.session.userId],
    (err, user) => {
      if (err) return next(err);
      if (!user) return res.redirect("/login");
      res.render("profile", { user, message: null, error: null });
    }
  );
});

app.post("/profile", requireLogin, (req, res, next) => {
  const { name, bio } = req.body;
  if (!name) {
    return db.get(
      "SELECT id, name, email, bio, created_at FROM users WHERE id = ?",
      [req.session.userId],
      (err, user) => {
        if (err) return next(err);
        res.render("profile", { user, message: null, error: "Name is required." });
      }
    );
  }
  db.run(
    "UPDATE users SET name = ?, bio = ? WHERE id = ?",
    [name, bio || "", req.session.userId],
    (err) => {
      if (err) return next(err);
      db.get(
        "SELECT id, name, email, bio, created_at FROM users WHERE id = ?",
        [req.session.userId],
        (err2, user) => {
          if (err2) return next(err2);
          res.render("profile", {
            user,
            message: "Profile updated!",
            error: null,
          });
        }
      );
    }
  );
});

// ---------- CORE PAGES ----------
app.get("/", (req, res) => res.redirect("/movies"));

app.get("/movies", (req, res) => {
  res.render("movies");
});

app.get("/tv", (req, res) => {
  res.render("tv");
});

// watch movie or tv: /watch?type=movie|tv&tmdbId=...&season=&episode=
app.get("/watch", (req, res) => {
  const { tmdbId } = req.query;
  if (!tmdbId) {
    return res.redirect("/movies");
  }
  res.render("watch");
});

// Watch party view: /party?code=ROOMCODE
app.get("/party", requireLogin, (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect("/movies");
  res.render("party");
});

// ---------- WATCH PARTY BACKEND (in-memory) ----------
const rooms = {};
const userLastMessageTime = {};
const MESSAGE_RATE_LIMIT = 5000; // 5s

function generateRoomCode() {
  let roomCode;
  do {
    roomCode = Math.random().toString(36).substr(2, 5).toUpperCase();
  } while (rooms[roomCode]);
  return roomCode;
}

// Create room
// GET /create-room?username=...
app.get("/create-room", (req, res) => {
  const username = req.query.username;
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }
  const code = generateRoomCode();
  rooms[code] = {
    currentTime: 0,
    videoUrl: "",
    lastActivity: Date.now(),
    roomName: `${username}'s room`,
    movieTitle: "",
    chat: [],
  };
  res.json({ roomCode: code });
});

// Set room details (embed URL + movieTitle)
app.get("/set-room-details/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  const { url, movieTitle } = req.query;
  const room = rooms[roomCode];
  if (!room) return res.status(404).json({ error: "Room not found" });

  room.videoUrl = url;
  room.movieTitle = movieTitle || "";
  room.lastActivity = Date.now();
  res.json({ success: true });
});

// Get current time
app.get("/time/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  const room = rooms[roomCode];
  if (!room) return res.status(404).json({ error: "Room not found" });
  room.lastActivity = Date.now();
  res.json({ currentTime: room.currentTime });
});

// Room details
app.get("/room-details/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  const room = rooms[roomCode];
  if (!room) return res.status(404).json({ error: "Room not found" });
  room.lastActivity = Date.now();
  res.json({
    videoUrl: room.videoUrl,
    roomName: room.roomName,
    movieTitle: room.movieTitle,
    chat: room.chat,
  });
});

// List rooms with a configured video
app.get("/rooms", (req, res) => {
  const list = Object.keys(rooms)
    .filter((code) => rooms[code].videoUrl)
    .map((code) => ({
      code,
      roomName: rooms[code].roomName,
      movieTitle: rooms[code].movieTitle,
    }));
  res.json(list);
});

// Chat messages
app.post("/send-message/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  const { username, profilePicture, message } = req.body;
  const room = rooms[roomCode];
  if (!room) return res.status(404).json({ error: "Room not found" });

  if (!username || !message) {
    return res
      .status(400)
      .json({ error: "Username and message are required" });
  }

  const now = Date.now();
  if (
    userLastMessageTime[username] &&
    now - userLastMessageTime[username] < MESSAGE_RATE_LIMIT
  ) {
    return res
      .status(429)
      .json({ error: "Slow down a bit before sending another message." });
  }

  userLastMessageTime[username] = now;
  room.chat.push({
    username,
    profilePicture,
    message,
    timestamp: now,
  });
  room.lastActivity = now;
  res.json({ success: true });
});

// Simulate server time progress (5s steps)
setInterval(() => {
  Object.keys(rooms).forEach((code) => {
    rooms[code].currentTime += 5;
  });
}, 5000);

// Cleanup inactive rooms (inactive > 30 min)
setInterval(() => {
  const now = Date.now();
  Object.keys(rooms).forEach((code) => {
    const room = rooms[code];
    if (!room.videoUrl || now - room.lastActivity > 30 * 60 * 1000) {
      delete rooms[code];
    }
  });
}, 5 * 60 * 1000);

// ---------- 404 ----------
app.use((req, res) => {
  res.status(404).render("404");
});

// ---------- ERROR HANDLER ----------
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send("Something went wrong.");
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Darkflix running on http://localhost:${PORT}`);
});
