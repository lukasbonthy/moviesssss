// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "app.db");
const db = new sqlite3.Database(dbPath);

// Create users table if not exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

function createUser({ name, email, passwordHash }) {
  return new Promise((resolve, reject) => {
    const stmt = `INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`;
    db.run(stmt, [name, email, passwordHash], function (err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, name, email });
    });
  });
}

function findUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function findUserById(id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function updateUserProfile(id, { name, bio }) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET name = ?, bio = ? WHERE id = ?`,
      [name, bio, id],
      function (err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      }
    );
  });
}

module.exports = {
  createUser,
  findUserByEmail,
  findUserById,
  updateUserProfile,
};
