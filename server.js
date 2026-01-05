// server.js
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const {
  createUser,
  findUserByEmail,
  findUserById,
  updateUserProfile,
} = require("./db");

const app = express();

// === CONFIG ===
const TMDB_API_KEY = process.env.TMDB_API_KEY || "YOUR_TMDB_API_KEY";

// In-memory movie party rooms (like your Vividx app)
const rooms = {};
const userLastMessageTime = {};
const MESSAGE_RATE_LIMIT = 5000; // 5 seconds

// === VIEW ENGINE ===
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// === MIDDLEWARE ===
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "10mb" })); // for JSON body (chat)

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-dev-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // set true + trust proxy when behind HTTPS
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// Expose current user to templates
app.use(async (req, res, next) => {
  if (!req.session.userId) {
    res.locals.currentUser = null;
    return next();
  }
  try {
    const user = await findUserById(req.session.userId);
    res.locals.currentUser = user || null;
  } catch (err) {
    console.error(err);
    res.locals.currentUser = null;
  }
  next();
});

// Auth guard
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

// === BASIC ROUTES ===

// Root -> movies or login
app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/movies");
  res.redirect("/login");
});

// SIGNUP
app.get("/signup", (req, res) => {
  res.render("signup", { error: null, values: { name: "", email: "" } });
});

app.post("/signup", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  const values = { name, email };

  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).render("signup", {
      error: "All fields are required.",
      values,
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).render("signup", {
      error: "Passwords do not match.",
      values,
    });
  }

  try {
    const existing = await findUserByEmail(email.trim().toLowerCase());
    if (existing) {
      return res.status(400).render("signup", {
        error: "A user with that email already exists.",
        values,
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
    });

    req.session.userId = user.id;
    res.redirect("/movies");
  } catch (err) {
    console.error(err);
    res.status(500).render("signup", {
      error: "Something went wrong. Please try again.",
      values,
    });
  }
});

// LOGIN
app.get("/login", (req, res) => {
  res.render("login", { error: null, values: { email: "" } });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const values = { email };

  if (!email || !password) {
    return res.status(400).render("login", {
      error: "Email and password are required.",
      values,
    });
  }

  try {
    const user = await findUserByEmail(email.trim().toLowerCase());
    if (!user) {
      return res.status(400).render("login", {
        error: "Invalid email or password.",
        values,
      });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(400).render("login", {
        error: "Invalid email or password.",
        values,
      });
    }

    req.session.userId = user.id;
    res.redirect("/movies");
  } catch (err) {
    console.error(err);
    res.status(500).render("login", {
      error: "Something went wrong. Please try again.",
      values,
    });
  }
});

// LOGOUT
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// PROFILE
app.get("/profile", requireAuth, async (req, res) => {
  try {
    const user = await findUserById(req.session.userId);
    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }
    res.render("profile", { user, message: null, error: null });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading profile");
  }
});

app.post("/profile", requireAuth, async (req, res) => {
  const { name, bio } = req.body;
  try {
    const user = await findUserById(req.session.userId);
    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }

    const newName = name && name.trim() ? name.trim() : user.name;
    const newBio = bio && bio.trim() ? bio.trim() : "";

    await updateUserProfile(user.id, { name: newName, bio: newBio });
    const updatedUser = await findUserById(user.id);

    res.render("profile", {
      user: updatedUser,
      message: "Profile updated successfully.",
      error: null,
    });
  } catch (err) {
    console.error(err);
    const user = await findUserById(req.session.userId);
    res.status(500).render("profile", {
      user,
      message: null,
      error: "Error updating profile.",
    });
  }
});

// MOVIES (Netflix-style home)
app.get("/movies", requireAuth, (req, res) => {
  res.render("movies", { tmdbApiKey: TMDB_API_KEY });
});

// WATCH (single-user watch page)
app.get("/watch", requireAuth, (req, res) => {
  res.render("watch", { tmdbApiKey: TMDB_API_KEY });
});

// WATCH PARTY PAGE
app.get("/party", requireAuth, (req, res) => {
  // just render; client JS will read ?code=... etc.
  res.render("party", { tmdbApiKey: TMDB_API_KEY });
});

// === MOVIE PARTY API (ported from Vividx) ===

// Helper: generate room code
function generateRoomCode() {
  let roomCode;
  do {
    roomCode = Math.random().toString(36).substr(2, 5).toUpperCase();
  } while (rooms[roomCode]);
  return roomCode;
}

// Create a new room
app.get("/create-room", requireAuth, (req, res) => {
  const username = req.query.username || (res.locals.currentUser && res.locals.currentUser.name);
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const roomCode = generateRoomCode();
  rooms[roomCode] = {
    currentTime: 0,
    videoUrl: "",
    lastActivity: Date.now(),
    roomName: `${username}'s room`,
    movieTitle: "",
    chat: [],
    users: new Set(),
  };
  res.json({ roomCode });
});

// Set video URL and movie title for a room
app.get("/set-room-details/:roomCode", requireAuth, (req, res) => {
  const roomCode = req.params.roomCode;
  const { url, movieTitle } = req.query;
  if (rooms[roomCode]) {
    rooms[roomCode].videoUrl = url;
    rooms[roomCode].movieTitle = movieTitle || "";
    rooms[roomCode].lastActivity = Date.now();
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "Room not found" });
  }
});

// Get the current time for a room
app.get("/time/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  if (rooms[roomCode]) {
    rooms[roomCode].lastActivity = Date.now();
    res.json({ currentTime: rooms[roomCode].currentTime });
  } else {
    res.status(404).json({ error: "Room not found" });
  }
});

// Get the video URL and other details for a room
app.get("/room-details/:roomCode", (req, res) => {
  const roomCode = req.params.roomCode;
  if (rooms[roomCode]) {
    rooms[roomCode].lastActivity = Date.now();
    const { videoUrl, roomName, movieTitle, chat } = rooms[roomCode];
    res.json({ videoUrl, roomName, movieTitle, chat });
  } else {
    res.status(404).json({ error: "Room not found" });
  }
});

// Get list of rooms (for potential lobby page)
app.get("/rooms", (req, res) => {
  const availableRooms = Object.keys(rooms)
    .filter((code) => rooms[code].videoUrl)
    .map((code) => ({
      code,
      roomName: rooms[code].roomName,
      movieTitle: rooms[code].movieTitle,
    }));
  res.json(availableRooms);
});

// Chat messages
app.post("/send-message/:roomCode", requireAuth, (req, res) => {
  const roomCode = req.params.roomCode;
  const { username, profilePicture, message } = req.body;
  const currentTime = Date.now();

  if (!username || !message) {
    return res
      .status(400)
      .json({ error: "Username and message are required" });
  }

  if (
    userLastMessageTime[username] &&
    currentTime - userLastMessageTime[username] < MESSAGE_RATE_LIMIT
  ) {
    return res.status(429).json({
      error:
        "You are sending messages too quickly. Please wait before sending another message.",
    });
  }

  userLastMessageTime[username] = currentTime;

  if (rooms[roomCode]) {
    rooms[roomCode].chat.push({
      username,
      profilePicture,
      message,
      timestamp: currentTime,
    });
    rooms[roomCode].lastActivity = currentTime;
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "Room not found" });
  }
});

// Increment video time for each room (server-side "clock")
setInterval(() => {
  Object.keys(rooms).forEach((code) => {
    rooms[code].currentTime += 5; // seconds
  });
}, 5000);

// Clean up inactive/empty rooms
setInterval(() => {
  const now = Date.now();
  Object.keys(rooms).forEach((code) => {
    const room = rooms[code];
    if (!room.videoUrl || now - room.lastActivity > 1 * 60 * 1000) {
      delete rooms[code];
    }
  });
}, 60 * 1000);

// 404
app.use((req, res) => {
  res.status(404).render("404");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
