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

// === VIEW ENGINE ===
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// === MIDDLEWARE ===
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-dev-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // set true + trust proxy when using HTTPS in production
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Expose current user to all templates
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

// === ROUTES ===

// Redirect root -> movies or login
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
    res.redirect("/movies"); // go straight to movies after signup
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

// WATCH (Netflix-style player page)
app.get("/watch", requireAuth, (req, res) => {
  res.render("watch", { tmdbApiKey: TMDB_API_KEY });
});

// 404
app.use((req, res) => {
  res.status(404).render("404");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
