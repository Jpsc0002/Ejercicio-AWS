// === BACKEND (server.js) ===
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./users.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Crear tabla si no existe
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )`);
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err) => {
    if (err) return res.status(400).json({ message: 'Error al registrar' });
    res.json({ message: 'Usuario registrado' });
  });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.json({ message: "Credenciales incorrectas" });
        }
        
        // Si el usuario es "admin", le damos el rol de admin
        const role = user.username === "admin" ? "admin" : "user";
        
        res.json({ message: "Login exitoso", username: user.username, role });
    });
});


app.get('/users', (req, res) => {
  db.all('SELECT id, username, email FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error en la base de datos' });
    res.json(rows);
  });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));